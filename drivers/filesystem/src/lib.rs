// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::CgroupHandle;
use agent_api::storage;
use agent_api::storage::{
    StorageError, VolumeAttacher, VolumeAttachment, VolumeHandle, VolumeId, VolumeProvider,
    VolumeSpec, VolumeState,
};
use macros::generated;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::{Span, debug, info, instrument};

pub struct FilesystemDriverConfig {
    /// Path where images are stored. Read-only.
    pub image_dir: PathBuf, // should be something like /var/lib/meister-agent/<uuid>/images
    /// Directory where .raw files as images are saved.
    pub volume_dir: PathBuf, // should be something like /var/lib/meister-agent/<uuid>/volumes
}

/// FileSystemBlockDriver manages <vm_id>.raw files in a specified directory to support block
/// devices for MeisterStack it is the basic implementation and should be used as fallback.
pub struct FilesystemBlockDriver {
    config: FilesystemDriverConfig,
}

impl FilesystemBlockDriver {
    pub fn new(config: FilesystemDriverConfig) -> storage::Result<Self> {
        if !config.image_dir.is_dir() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "image_dir does not exist: {}",
                config.image_dir.display()
            )));
        }
        std::fs::create_dir_all(&config.volume_dir).map_err(|e| StorageError::Backend(e.into()))?;
        Ok(Self { config })
    }

    fn volume_path(&self, id: &VolumeId) -> PathBuf {
        self.config.volume_dir.join(format!("{id}.raw"))
    }

    fn tmp_path(&self, id: &VolumeId) -> PathBuf {
        self.config.volume_dir.join(format!("{id}.tmp"))
    }

    /// How big the file is, or `NotFound`. One implementation behind both
    /// `describe` and `stat`, because for this backend they are one question:
    /// there is no connection to be down while the data is up.
    async fn measure(&self, id: &VolumeId) -> storage::Result<VolumeState> {
        match tokio::fs::metadata(self.volume_path(id)).await {
            Ok(meta) => Ok(VolumeState {
                size_bytes: meta.len(),
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StorageError::NotFound(*id)),
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }

    #[generated(model = ClaudeFable, version = "5")]
    fn clone_or_copy(src: &Path, dst: &Path) -> std::io::Result<u64> {
        use nix::errno::Errno;
        use nix::fcntl::copy_file_range;

        let src_file = std::fs::File::open(src)?;
        let dst_file = std::fs::File::create(dst)?;
        let total = src_file.metadata()?.len();

        let mut remaining = total as usize;
        let mut first_call = true;

        while remaining > 0 {
            match copy_file_range(&src_file, None, &dst_file, None, remaining) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "copy_file_range returned 0 before EOF",
                    ));
                }
                Ok(n) => {
                    remaining -= n;
                    first_call = false;
                }
                Err(e @ (Errno::EOPNOTSUPP | Errno::EXDEV | Errno::EINVAL)) if first_call => {
                    let _ = e;
                    drop(dst_file);
                    let mut s = std::fs::File::open(src)?;
                    let mut d = std::fs::File::create(dst)?;
                    return std::io::copy(&mut s, &mut d);
                }
                Err(e) => return Err(std::io::Error::from_raw_os_error(e as i32)),
            }
        }
        Ok(total)
    }
}

/// The volume half. `spec.driver` has already routed the call here and
/// `spec.params` is a backend's business — this one has no options, so it
/// takes none.
#[async_trait::async_trait]
impl VolumeProvider for FilesystemBlockDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> storage::Result<VolumeHandle> {
        let path = self.volume_path(id);
        let handle = |size_bytes| VolumeHandle {
            id: *id,
            backend: path.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        };

        match tokio::fs::metadata(&path).await {
            Ok(meta) => {
                // The idempotence the provider contract asks for, and the one
                // this backend has always had: the file IS the volume, and it
                // is named after the id.
                debug!(size_bytes = meta.len(), "volume already exists");
                return Ok(handle(meta.len()));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(StorageError::Backend(e.into())),
        }

        let src = match &spec.base_image {
            Some(name) => {
                let src = self.config.image_dir.join(name);
                let meta = tokio::fs::metadata(&src)
                    .await
                    .map_err(|_| StorageError::ImageNotFound(name.clone()))?;
                if meta.len() > spec.size_bytes {
                    return Err(StorageError::InvalidSpec(format!(
                        "size_bytes {} smaller than base image {} ({} bytes)",
                        spec.size_bytes,
                        name,
                        meta.len()
                    )));
                }
                Some(src)
            }
            None => None,
        };
        let tmp = self.tmp_path(id);
        let final_path = path.clone();
        let size = spec.size_bytes;

        let span = Span::current();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            span.in_scope(|| {
                match &src {
                    Some(s) => {
                        debug!(base = %s.display(), "cloning base image");
                        Self::clone_or_copy(s, &tmp)?;
                    }
                    None => {
                        std::fs::File::create(&tmp)?;
                    }
                }
                let f = std::fs::OpenOptions::new().write(true).open(&tmp)?;
                f.set_len(size)?;
                f.sync_all()?;
                std::fs::rename(&tmp, &final_path)?;
                Ok(())
            })
        })
        .await
        .map_err(|e| StorageError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(|e| StorageError::Backend(e.into()))?;

        info!("volume ready");
        Ok(handle(size))
    }

    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> storage::Result<()> {
        let id = &handle.id;
        for p in [self.tmp_path(id), self.volume_path(id)] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => debug!(path = %p.display(), "volume file removed"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Backend(e.into())),
            }
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn describe(&self, handle: &VolumeHandle) -> storage::Result<VolumeState> {
        self.measure(&handle.id).await
    }
}

/// The connection half, and the degenerate case the whole split has to keep
/// cheap: a file is not a process, so attaching one is naming it and
/// detaching one is nothing at all. No cgroup is taken because there is
/// nothing to confine, and `stat` and `describe` give the same answer because
/// for this backend the volume and the connection are the same object.
#[async_trait::async_trait]
impl VolumeAttacher for FilesystemBlockDriver {
    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn attach(
        &self,
        handle: &VolumeHandle,
        _cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<VolumeAttachment> {
        Ok(VolumeAttachment::Path(handle.path()))
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn stat(
        &self,
        handle: &VolumeHandle,
        _attachment: &VolumeAttachment,
    ) -> storage::Result<VolumeState> {
        self.measure(&handle.id).await
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use agent_api::storage::VolumeSpec;
    use uuid::Uuid;

    fn driver(tag: &str) -> (FilesystemBlockDriver, PathBuf) {
        let root = std::env::temp_dir().join(format!("meister-fs-{tag}-{}", std::process::id()));
        let images = root.join("images");
        let volumes = root.join("volumes");
        std::fs::create_dir_all(&images).expect("a temp image dir");
        let _ = std::fs::remove_dir_all(&volumes);
        let driver = FilesystemBlockDriver::new(FilesystemDriverConfig {
            image_dir: images,
            volume_dir: volumes.clone(),
        })
        .expect("the driver builds");
        (driver, volumes)
    }

    fn spec(size_bytes: u64) -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes,
            driver: None,
            params: None,
        }
    }

    /// The degeneration probe, and the reason it is in the plainest backend:
    /// splitting one verb into two must not change what a VM gets.
    ///
    /// `create` used to return `Path(<volume_dir>/<id>.raw)` and a size, in
    /// one call. Provision and attach now produce exactly that — the same
    /// path, the same file, the same length — and `VolumeAttachment` did not
    /// change, so an `InstanceSpec` built from it is the same list of the
    /// same variants and the VMM config below it is byte for byte the config
    /// it was.
    #[tokio::test]
    async fn provision_then_attach_is_what_one_create_used_to_return() {
        let (driver, volumes) = driver("degenerate");
        let id = Uuid::new_v4();

        let handle = driver
            .provision(&id, &spec(4096))
            .await
            .expect("provisioned");
        assert_eq!(handle.id, id);
        assert_eq!(handle.size_bytes, 4096);
        assert_eq!(handle.path(), volumes.join(format!("{id}.raw")));

        // The bytes are there before anything is attached to them: that is
        // the sentence the split exists to make true.
        let meta = std::fs::metadata(handle.path()).expect("the file exists after provision alone");
        assert_eq!(meta.len(), 4096);

        let attachment = driver.attach(&handle, None).await.expect("attached");
        match &attachment {
            VolumeAttachment::Path(p) => assert_eq!(p, &volumes.join(format!("{id}.raw"))),
            other => panic!("a file is a path, not {other:?}"),
        }
        // And what the VMM is told is the same shape it was told before: a
        // block volume, no shared memory, no backend process to keep alive.
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);
    }

    /// Attaching takes no cgroup because a file is not a process, and
    /// detaching is nothing at all. The two halves of "this backend
    /// degenerates cleanly": a volume that outlives its VM loses nothing when
    /// the VM goes, because the attachment held nothing.
    #[tokio::test]
    async fn a_file_survives_a_detach_untouched() {
        let (driver, _) = driver("detach");
        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(2048)).await.unwrap();
        let attachment = driver.attach(&handle, None).await.unwrap();

        driver
            .detach(&handle, &attachment)
            .await
            .expect("nothing to do");
        assert_eq!(
            driver.describe(&handle).await.expect("still there"),
            VolumeState { size_bytes: 2048 },
            "detaching a file must not touch the file"
        );
        // stat asks the same question one layer out, and for this backend
        // gets the same answer: there is no connection to be down.
        assert_eq!(
            driver.stat(&handle, &attachment).await.unwrap(),
            VolumeState { size_bytes: 2048 }
        );
    }

    /// Deleting the data needs a handle and nothing else — no attachment
    /// anywhere in the call. This is the signature the old trait could not
    /// write, and the one a volume outliving its VM needs.
    #[tokio::test]
    async fn deprovision_needs_no_attachment_and_is_idempotent() {
        let (driver, _) = driver("deprovision");
        let id = Uuid::new_v4();
        let handle = driver.provision(&id, &spec(1024)).await.unwrap();

        driver.deprovision(&handle).await.expect("removed");
        assert!(matches!(
            driver.describe(&handle).await,
            Err(StorageError::NotFound(gone)) if gone == id
        ));
        // Twice is Ok: teardown runs again after a crash between the two
        // halves of it.
        driver.deprovision(&handle).await.expect("idempotent");
    }

    /// Provisioning twice is one volume. The rule the whole idempotence
    /// contract rests on: a provision whose handle is lost — a controller
    /// that died before writing it down — must be FOUND again rather than
    /// answered with a second volume, and the name derived from the id is
    /// what makes that true.
    #[tokio::test]
    async fn a_lost_handle_finds_the_same_volume_rather_than_making_a_second() {
        let (driver, _) = driver("idempotent");
        let id = Uuid::new_v4();

        let first = driver.provision(&id, &spec(4096)).await.unwrap();
        // The size the second call asks for is deliberately different: what
        // comes back has to be the volume that EXISTS, not a new one.
        let again = driver.provision(&id, &spec(8192)).await.unwrap();
        assert_eq!(first.backend, again.backend);
        assert_eq!(
            again.size_bytes, 4096,
            "the volume that is there is the answer"
        );
    }
}
