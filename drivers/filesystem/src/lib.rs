// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::CgroupHandle;
use agent_api::storage;
use agent_api::storage::{
    BlockDriver, StorageError, Volume, VolumeAttachment, VolumeId, VolumeSpec,
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

#[async_trait::async_trait]
impl BlockDriver for FilesystemBlockDriver {
    /// `spec.driver` has already routed the call here and `spec.params` is a
    /// backend's business — this one has no options, so it takes none. And no
    /// cgroup: a file is not a process, so there is nothing to confine.
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn create(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
        _cgroup: Option<&CgroupHandle>,
    ) -> storage::Result<Volume> {
        let path = self.volume_path(id);

        match tokio::fs::metadata(&path).await {
            Ok(meta) => {
                debug!(size_bytes = meta.len(), "volume already exists");
                return Ok(Volume {
                    id: *id,
                    attachment: VolumeAttachment::Path(path),
                    size_bytes: meta.len(),
                });
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
        Ok(Volume {
            id: *id,
            attachment: VolumeAttachment::Path(path),
            size_bytes: size,
        })
    }

    #[instrument(skip_all, fields(volume_id = %id))]
    async fn destroy(&self, id: &VolumeId, _attachment: &VolumeAttachment) -> storage::Result<()> {
        for p in [self.tmp_path(id), self.volume_path(id)] {
            match tokio::fs::remove_file(&p).await {
                Ok(()) => debug!(path = %p.display(), "volume file removed"),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Backend(e.into())),
            }
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn get(&self, id: &VolumeId, _attachment: &VolumeAttachment) -> storage::Result<Volume> {
        let path = self.volume_path(id);
        match tokio::fs::metadata(&path).await {
            Ok(meta) => Ok(Volume {
                id: *id,
                attachment: VolumeAttachment::Path(path),
                size_bytes: meta.len(),
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StorageError::NotFound(*id)),
            Err(e) => Err(StorageError::Backend(e.into())),
        }
    }
}
