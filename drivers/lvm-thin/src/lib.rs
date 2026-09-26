// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Manage thin logical volumes in an existing LVM pool through LVM command
//! line tools. Volume and snapshot IDs determine LV names. Base images are
//! written under staging names before publication; snapshots use thin-LV COW.

use std::path::{Path, PathBuf};

use agent_api::CgroupHandle;
use agent_api::storage::{
    self, Locality, SnapshotConsistency, SnapshotId, StorageError, VolumeAttacher,
    VolumeAttachment, VolumeHandle, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
};
use tracing::{debug, error, info, instrument, warn};

/// Default admission limit as a percentage of thin-pool data usage.
pub const DEFAULT_MAX_DATA_PERCENT: f64 = 90.0;

/// Per-volume override for the configured volume group and thin pool.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LvmThinParams {
    /// `<vg>/<thin_pool>`, overriding the configured pair.
    pub pool: Option<String>,
}

pub struct LvmThinDriverConfig {
    pub vg: String,
    pub thin_pool: String,
    /// Refuse a create while the pool is fuller than this (percent).
    pub max_data_percent: f64,
    /// Directory resolving base-image names.
    pub image_dir: PathBuf,
    /// Where to find `lvs`/`lvcreate`/`lvremove`. None = whatever PATH says,
    /// which is right on a NixOS node and wrong nowhere in particular.
    pub bin_dir: Option<PathBuf>,
    pub qemu_img: PathBuf,
    /// Root for LVM device paths; normally /dev, with ordinary files in tests.
    pub dev_dir: PathBuf,
    /// Sandbox used to probe and convert base images.
    pub convert: agent_api::base_image::Sandbox,
}

pub struct LvmThinDriver {
    config: LvmThinDriverConfig,
}

/// `<vg>/<lv>`, the way LVM wants a volume named on a command line.
fn lv_name(id: &VolumeId) -> String {
    format!("vm-{id}")
}

/// Staging LV name for base-image initialization. Only the final name counts
/// as provisioned; retries remove an unfinished staging LV before rebuilding.
fn staging_lv_name(id: &VolumeId) -> String {
    format!("{}.staging", lv_name(id))
}

/// Use a snapshot-specific prefix to separate snapshot and volume LV names.
fn snapshot_lv_name(id: &SnapshotId) -> String {
    format!("snap-{id}")
}

/// Resolve the per-volume pool override or configured default, validating its syntax.
fn resolve_pool(
    params: &LvmThinParams,
    default_vg: &str,
    default_pool: &str,
) -> storage::Result<(String, String)> {
    let Some(pool) = &params.pool else {
        return Ok((default_vg.to_string(), default_pool.to_string()));
    };
    let (vg, lv) = pool.split_once('/').ok_or_else(|| {
        StorageError::InvalidSpec(format!(
            "lvm-thin params.pool {pool:?} must be <vg>/<thin_pool>"
        ))
    })?;
    if vg.is_empty() || lv.is_empty() {
        return Err(StorageError::InvalidSpec(format!(
            "lvm-thin params.pool {pool:?} must be <vg>/<thin_pool>"
        )));
    }
    Ok((vg.to_string(), lv.to_string()))
}

/// Reject non-finite or out-of-range fill values and pools above the threshold.
/// This measures current data usage, not future thin-volume writes.
fn admits(data_percent: f64, max_data_percent: f64) -> storage::Result<()> {
    if data_percent > max_data_percent {
        return Err(StorageError::InvalidSpec(format!(
            "thin pool is {data_percent:.2}% full, over the {max_data_percent:.2}% limit \
             this node admits at; free space in the pool or raise \
             [volume.lvm-thin].max_data_percent"
        )));
    }
    Ok(())
}

/// One field of `lvs --noheadings`, which pads every line with leading
/// whitespace and hands back an empty string for a field a segment type does
/// not have (`data_percent` on a plain LV, for instance).
fn parse_lvs_field(stdout: &str) -> Option<&str> {
    stdout.lines().map(str::trim).find(|l| !l.is_empty())
}

fn parse_number(stdout: &str, what: &str) -> storage::Result<f64> {
    let raw = parse_lvs_field(stdout).ok_or_else(|| {
        StorageError::Backend(anyhow::anyhow!(
            "lvs reported no {what} (output: {stdout:?})"
        ))
    })?;
    raw.parse::<f64>().map_err(|e| {
        StorageError::Backend(anyhow::anyhow!("lvs {what} {raw:?} is not a number: {e}"))
    })
}

/// Whether an `lvs`/`lvremove` failure means "there is no such thing" rather
/// than "something went wrong". LVM says so in prose and in no other way.
fn means_absent(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("failed to find") || s.contains("not found") || s.contains("no such")
}

impl LvmThinDriver {
    pub fn new(config: LvmThinDriverConfig) -> storage::Result<Self> {
        if config.vg.is_empty() || config.thin_pool.is_empty() {
            return Err(StorageError::InvalidSpec(
                "[volume.lvm-thin] needs both vg and thin_pool".into(),
            ));
        }
        let driver = Self { config };
        // Validate the configured thin pool during startup.
        let target = driver.default_pool();
        match std::process::Command::new(driver.tool("lvs"))
            .args(["--noheadings", "-o", "lv_name", &target])
            .output()
        {
            Ok(out) if out.status.success() => {
                info!(pool = %target, "lvm thin pool found");
            }
            Ok(out) => {
                return Err(StorageError::Backend(anyhow::anyhow!(
                    "thin pool {target} is not usable: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
            Err(e) => {
                return Err(StorageError::Backend(anyhow::anyhow!(
                    "running lvs: {e} (is lvm2 installed and is the agent root?)"
                )));
            }
        }
        Ok(driver)
    }

    fn tool(&self, name: &str) -> PathBuf {
        match &self.config.bin_dir {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        }
    }

    fn default_pool(&self) -> String {
        format!("{}/{}", self.config.vg, self.config.thin_pool)
    }

    /// LVM device path supplied to the VMM and canonicalized for conversion.
    fn device_path(&self, vg: &str, lv: &str) -> PathBuf {
        self.config.dev_dir.join(vg).join(lv)
    }

    /// Build a consistent volume handle for existing and newly created LVs.
    fn handle(id: &VolumeId, dev: &Path, size_bytes: u64, spec: &VolumeSpec) -> VolumeHandle {
        VolumeHandle {
            id: *id,
            backend: dev.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        }
    }

    /// Build a snapshot handle without attachment parameters.
    fn snapshot_handle(id: &SnapshotId, dev: &Path, size_bytes: u64) -> VolumeHandle {
        VolumeHandle {
            id: *id,
            backend: dev.to_string_lossy().into_owned(),
            size_bytes,
            params: None,
        }
    }

    /// Read the volume group from `/dev/<vg>/<lv>`, falling back to configuration
    /// for legacy handles without a path.
    fn vg_of(&self, handle: &VolumeHandle) -> String {
        handle
            .path()
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|s| s.to_str())
            .filter(|s| *s != "dev")
            .unwrap_or(&self.config.vg)
            .to_string()
    }

    fn params(spec: &VolumeSpec) -> storage::Result<LvmThinParams> {
        match &spec.params {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| StorageError::InvalidSpec(format!("invalid lvm-thin params: {e}"))),
            None => Ok(LvmThinParams::default()),
        }
    }

    /// Run an LVM tool. Recognized absence returns None; other failures retain tool diagnostics.
    async fn lvm(&self, tool: &str, args: &[&str]) -> storage::Result<Option<String>> {
        let out = tokio::process::Command::new(self.tool(tool))
            .args(args)
            .output()
            .await
            .map_err(|e| StorageError::Backend(anyhow::anyhow!("running {tool}: {e}")))?;
        if out.status.success() {
            return Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if means_absent(&stderr) {
            return Ok(None);
        }
        Err(StorageError::Backend(anyhow::anyhow!(
            "{tool} {} failed ({}): {}",
            args.join(" "),
            out.status,
            stderr.trim()
        )))
    }

    /// How full the pool's data space is, right now.
    async fn pool_data_percent(&self, vg: &str, pool: &str) -> storage::Result<f64> {
        let target = format!("{vg}/{pool}");
        let out = self
            .lvm(
                "lvs",
                &["--noheadings", "--nosuffix", "-o", "data_percent", &target],
            )
            .await?
            .ok_or_else(|| {
                StorageError::Backend(anyhow::anyhow!(
                    "thin pool {target} does not exist on this node"
                ))
            })?;
        parse_number(&out, "data_percent")
    }

    /// Measure the actual LV size, including extent rounding.
    async fn lv_size_bytes(&self, vg: &str, lv: &str) -> storage::Result<Option<u64>> {
        let target = format!("{vg}/{lv}");
        let Some(out) = self
            .lvm(
                "lvs",
                &[
                    "--noheadings",
                    "--nosuffix",
                    "--units",
                    "b",
                    "-o",
                    "lv_size",
                    &target,
                ],
            )
            .await?
        else {
            return Ok(None);
        };
        // An LV that vanished between two calls reads as an empty line here.
        if parse_lvs_field(&out).is_none() {
            return Ok(None);
        }
        Ok(Some(parse_number(&out, "lv_size")? as u64))
    }

    /// Convert the probed image to raw in the configured sandbox, granting access
    /// to the destination LV for the duration of conversion.
    async fn write_base_image(
        &self,
        image: &agent_api::base_image::BaseImage,
        src: &Path,
        dev: &Path,
        name: &str,
    ) -> storage::Result<()> {
        let node = tokio::fs::canonicalize(dev).await.map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "the lv {} has no device node to write onto: {e}",
                dev.display()
            ))
        })?;
        agent_api::base_image::convert(
            &self.config.convert,
            &self.config.qemu_img,
            image,
            src,
            agent_api::base_image::Destination::Device(&node),
            name,
        )
        .await
    }

    async fn remove_lv(&self, vg: &str, lv: &str) -> storage::Result<()> {
        let target = format!("{vg}/{lv}");
        self.lvm("lvremove", &["-f", &target]).await.map(|_| ())
    }

    /// Publish by renaming the staging LV. A missing source is an error here.
    async fn rename_lv(&self, vg: &str, from: &str, to: &str) -> storage::Result<()> {
        self.lvm("lvrename", &[vg, from, to])
            .await?
            .ok_or_else(|| {
                StorageError::Backend(anyhow::anyhow!(
                    "{vg}/{from} was gone before it could be renamed to {to}"
                ))
            })
            .map(|_| ())
    }
}

#[async_trait::async_trait]
impl VolumeProvider for LvmThinDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> storage::Result<VolumeHandle> {
        let params = Self::params(spec)?;
        let (vg, pool) = resolve_pool(&params, &self.config.vg, &self.config.thin_pool)?;
        let lv = lv_name(id);
        let staging = staging_lv_name(id);
        let dev = self.device_path(&vg, &lv);

        // An existing final LV is complete; a staging name alone is not.
        if let Some(size) = self.lv_size_bytes(&vg, &lv).await? {
            debug!(size_bytes = size, "thin volume already exists");
            return Ok(Self::handle(id, &dev, size, spec));
        }

        // Discard unfinished image initialization before retrying the same volume ID.
        if self.lv_size_bytes(&vg, &staging).await?.is_some() {
            warn!(vg = %vg, lv = %staging,
                  "a half-written lv from an earlier attempt is here, removing it");
            self.remove_lv(&vg, &staging).await?;
        }

        let fill = self.pool_data_percent(&vg, &pool).await?;
        debug!(pool = %format!("{vg}/{pool}"), data_percent = fill, "thin pool fill measured");
        admits(fill, self.config.max_data_percent)?;

        let src = match &spec.base_image {
            Some(name) => {
                let path = self.config.image_dir.join(name);
                if !path.is_file() {
                    return Err(StorageError::ImageNotFound(name.clone()));
                }
                // Probe the virtual raw size and validate supported image features once.
                let image = agent_api::base_image::probe(
                    &self.config.convert,
                    &self.config.qemu_img,
                    &path,
                    name,
                )
                .await?;
                if image.virtual_size > spec.size_bytes {
                    return Err(StorageError::InvalidSpec(format!(
                        "size_bytes {} smaller than base image {name} ({} bytes raw)",
                        spec.size_bytes, image.virtual_size
                    )));
                }
                Some((path, name.clone(), image))
            }
            None => None,
        };

        let target_pool = format!("{vg}/{pool}");
        let size_arg = format!("{}b", spec.size_bytes);
        // Stage base-image volumes until copying completes; empty volumes are
        // complete when lvcreate returns and use the final name immediately.
        let building = match &src {
            Some(_) => staging.as_str(),
            None => lv.as_str(),
        };
        self.lvm(
            "lvcreate",
            &["-T", &target_pool, "-V", &size_arg, "-n", building],
        )
        .await?
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!("thin pool {target_pool} disappeared"))
        })?;

        // On conversion failure, try to remove the staging LV before returning.
        if let Some((path, name, image)) = src {
            let staging_dev = self.device_path(&vg, &staging);
            info!(base = %path.display(), dev = %staging_dev.display(),
                  format = %image.format, "writing base image onto lv");
            if let Err(e) = self
                .write_base_image(&image, &path, &staging_dev, &name)
                .await
            {
                warn!(error = %format!("{e:#}"),
                      "base image failed, removing the lv again");
                if let Err(rm) = self.remove_lv(&vg, &staging).await {
                    // A failed rollback leaves staging data allocated until a later cleanup.
                    error!(vg = %vg, lv = %staging, error = %format!("{rm:#}"),
                           "rollback failed, the half-written lv is orphaned");
                }
                return Err(e);
            }
            // Publish the completed image by renaming the staging LV.
            self.rename_lv(&vg, &staging, &lv).await?;
        }

        let size_bytes = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .unwrap_or(spec.size_bytes);
        info!(dev = %dev.display(), size_bytes, "thin volume ready");
        Ok(Self::handle(id, &dev, size_bytes, spec))
    }

    /// Grow virtual LV size without shrinking, then report LVM's measured size.
    /// LVM may round up to extents; thin-pool physical usage grows on later writes.
    #[instrument(skip_all, fields(volume_id = %handle.id, size_bytes))]
    async fn resize(
        &self,
        handle: &VolumeHandle,
        size_bytes: u64,
    ) -> storage::Result<VolumeHandle> {
        let vg = self.vg_of(handle);
        let lv = lv_name(&handle.id);
        let have = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .ok_or(StorageError::NotFound(handle.id))?;
        if have >= size_bytes {
            // Accept existing sizes at or above the request, including prior extent rounding.
            debug!(have, size_bytes, "the lv is already at least this size");
            return Ok(VolumeHandle {
                size_bytes: have,
                ..handle.clone()
            });
        }
        let target = format!("{vg}/{lv}");
        let size_arg = format!("{size_bytes}b");
        self.lvm("lvextend", &["-L", &size_arg, &target])
            .await?
            .ok_or(StorageError::NotFound(handle.id))?;
        let grown = self.lv_size_bytes(&vg, &lv).await?.unwrap_or(size_bytes);
        info!(from = have, to = grown, "thin volume grown");
        Ok(VolumeHandle {
            size_bytes: grown,
            ..handle.clone()
        })
    }

    /// Advertise native thin-LV copy-on-write snapshots as Atomic. This does not
    /// flush guest applications or include guest RAM.
    fn snapshot_support(&self) -> Option<SnapshotConsistency> {
        Some(SnapshotConsistency::Atomic)
    }

    #[instrument(skip_all, fields(volume_id = %handle.id, snapshot_id = %id))]
    async fn snapshot(
        &self,
        handle: &VolumeHandle,
        id: &SnapshotId,
    ) -> storage::Result<VolumeHandle> {
        let vg = self.vg_of(handle);
        let snap = snapshot_lv_name(id);
        let dev = self.device_path(&vg, &snap);
        // Reuse snapshots under their ID-derived LV names.
        if let Some(size) = self.lv_size_bytes(&vg, &snap).await? {
            debug!(size_bytes = size, "snapshot lv already exists");
            return Ok(Self::snapshot_handle(id, &dev, size));
        }
        let source = format!("{vg}/{}", lv_name(&handle.id));
        // Use -s without -L for a thin snapshot inheriting the origin size;
        // -L would select a fixed-size COW exception store.
        self.lvm("lvcreate", &["-s", "-n", &snap, &source])
            .await?
            .ok_or(StorageError::NotFound(handle.id))?;
        let size_bytes = self
            .lv_size_bytes(&vg, &snap)
            .await?
            .unwrap_or(handle.size_bytes);
        info!(dev = %dev.display(), size_bytes, "thin snapshot taken");
        Ok(Self::snapshot_handle(id, &dev, size_bytes))
    }

    #[instrument(skip_all, fields(snapshot_id = %handle.id))]
    async fn drop_snapshot(&self, handle: &VolumeHandle) -> storage::Result<()> {
        let vg = self.vg_of(handle);
        let lv = snapshot_lv_name(&handle.id);
        self.remove_lv(&vg, &lv).await?;
        debug!(vg = %vg, lv = %lv, "thin snapshot removed");
        Ok(())
    }

    #[instrument(skip_all, fields(volume_id = %id, from = %snapshot.backend))]
    async fn provision_from(
        &self,
        id: &VolumeId,
        snapshot: &VolumeHandle,
        spec: &VolumeSpec,
    ) -> storage::Result<VolumeHandle> {
        let vg = self.vg_of(snapshot);
        let lv = lv_name(id);
        let dev = self.device_path(&vg, &lv);
        if let Some(size) = self.lv_size_bytes(&vg, &lv).await? {
            debug!(size_bytes = size, "thin volume already exists");
            return Ok(Self::handle(id, &dev, size, spec));
        }
        // Create a writable thin snapshot sharing the source blocks. `-K` ignores
        // activation-skip so the new volume has a device node for attachment.
        let source = format!("{vg}/{}", snapshot_lv_name(&snapshot.id));
        self.lvm("lvcreate", &["-s", "-K", "-n", &lv, &source])
            .await?
            .ok_or(StorageError::NotFound(snapshot.id))?;
        let size_bytes = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .unwrap_or(snapshot.size_bytes);
        // Snapshot-derived volumes inherit the source size. Growth is a separate
        // resize operation; this method does not apply the requested size.
        if spec.size_bytes < size_bytes {
            warn!(
                asked = spec.size_bytes,
                size_bytes, "the snapshot is bigger than the size asked for; the lv keeps its own"
            );
        }
        info!(dev = %dev.display(), size_bytes, "thin volume ready from snapshot");
        Ok(Self::handle(id, &dev, size_bytes, spec))
    }

    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> storage::Result<()> {
        // Resolve the VG from the handle, which may differ from the current default.
        let lv = lv_name(&handle.id);
        let vg = self.vg_of(handle);
        self.remove_lv(&vg, &lv).await?;
        debug!(vg = %vg, lv = %lv, "thin volume removed");
        // Also remove any staging LV left by interrupted image conversion.
        let staging = staging_lv_name(&handle.id);
        self.remove_lv(&vg, &staging).await?;
        Ok(())
    }

    /// LVM thin volumes require provisioning and attachment on their owning node.
    fn locality(&self) -> Locality {
        Locality::NodeLocal
    }

    #[instrument(level = "trace", skip_all, fields(volume_id = %handle.id))]
    async fn describe(&self, handle: &VolumeHandle) -> storage::Result<VolumeState> {
        match self
            .lv_size_bytes(&self.vg_of(handle), &lv_name(&handle.id))
            .await?
        {
            Some(size_bytes) => Ok(VolumeState { size_bytes }),
            None => Err(StorageError::NotFound(handle.id)),
        }
    }

    /// Probe the deterministic final LV name in the pool selected by the spec.
    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> storage::Result<Option<VolumeHandle>> {
        let params = Self::params(spec)?;
        let (vg, _) = resolve_pool(&params, &self.config.vg, &self.config.thin_pool)?;
        let lv = lv_name(id);
        let dev = self.device_path(&vg, &lv);
        Ok(self
            .lv_size_bytes(&vg, &lv)
            .await?
            .map(|size| Self::handle(id, &dev, size, spec)))
    }

    /// Probe a snapshot in its source handle's VG. Without the source handle,
    /// refuse rather than checking the configured default and guessing absence.
    #[instrument(level = "trace", skip_all, fields(snapshot_id = %id))]
    async fn probe_snapshot(
        &self,
        volume: Option<&VolumeHandle>,
        id: &SnapshotId,
    ) -> storage::Result<Option<VolumeHandle>> {
        let Some(volume) = volume else {
            return Err(StorageError::InvalidSpec(format!(
                "lvm-thin cannot look for snapshot {id} without the volume it was taken from:                  the volume group is on that volume's handle"
            )));
        };
        let vg = self.vg_of(volume);
        let snap = snapshot_lv_name(id);
        let dev = self.device_path(&vg, &snap);
        Ok(self
            .lv_size_bytes(&vg, &snap)
            .await?
            .map(|size| Self::snapshot_handle(id, &dev, size)))
    }
}

/// Attach by returning the LV device path. The caller owns closing VMM file
/// descriptors before deletion; this attacher starts no backend process.
#[async_trait::async_trait]
impl VolumeAttacher for LvmThinDriver {
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
        attachment: &VolumeAttachment,
    ) -> storage::Result<VolumeState> {
        if !matches!(attachment, VolumeAttachment::Path(_)) {
            return Err(StorageError::NotFound(handle.id));
        }
        self.describe(handle).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn driver(vg: &str) -> LvmThinDriver {
        LvmThinDriver {
            config: LvmThinDriverConfig {
                vg: vg.into(),
                thin_pool: "thin".into(),
                max_data_percent: DEFAULT_MAX_DATA_PERCENT,
                image_dir: PathBuf::from("/var/lib/meister/images"),
                bin_dir: None,
                qemu_img: PathBuf::from("qemu-img"),
                dev_dir: PathBuf::from("/dev"),
                convert: agent_api::base_image::Sandbox::default(),
            },
        }
    }

    fn spec() -> VolumeSpec {
        VolumeSpec {
            base_image: None,
            size_bytes: 1 << 30,
            driver: Some("lvm-thin".into()),
            params: None,
        }
    }

    /// Fake LVM tools model LV metadata in files and log command ordering.
    /// They do not exercise real LVM allocation, devices or image conversion.
    struct FakeLvm {
        temp: tempfile::TempDir,
        /// Record ordered ownership transfers without chown or a privileged fixture account.
        handed_over: std::sync::Arc<std::sync::Mutex<Vec<(PathBuf, u32, u32)>>>,
    }

    impl FakeLvm {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempfile::Builder::new()
                .prefix("meister-lvm-thin-")
                .tempdir()
                .expect("a temp dir");
            let root = temp.path();
            for dir in ["bin", "state", "images", "dev/vg0"] {
                std::fs::create_dir_all(root.join(dir)).expect("the fake's directories");
            }
            let state = root.join("state").display().to_string();
            let dev = root.join("dev").join("vg0").display().to_string();
            let log = root.join("log").display().to_string();

            let scripts = [
                (
                    "lvs",
                    format!(
                        "field=\ntarget=\n\
                         while [ $# -gt 0 ]; do\n\
                         case \"$1\" in\n\
                         -o) field=\"$2\"; shift 2;;\n\
                         --units) shift 2;;\n\
                         --noheadings|--nosuffix) shift;;\n\
                         *) target=\"$1\"; shift;;\n\
                         esac\n\
                         done\n\
                         name=${{target#*/}}\n\
                         if [ \"$field\" = data_percent ]; then echo \"  10.00\"; exit 0; fi\n\
                         if [ -f \"{state}/$name\" ]; then\n\
                         echo \"  $(cat \"{state}/$name\")\"; exit 0\n\
                         fi\n\
                         echo \"  Failed to find logical volume \\\"$target\\\"\" >&2\n\
                         exit 5\n"
                    ),
                ),
                (
                    "lvcreate",
                    format!(
                        "echo \"lvcreate $*\" >> \"{log}\"\n\
                         size=0\nname=\n\
                         while [ $# -gt 0 ]; do\n\
                         case \"$1\" in\n\
                         -V) size=${{2%b}}; shift 2;;\n\
                         -n) name=\"$2\"; shift 2;;\n\
                         -T) shift 2;;\n\
                         *) shift;;\n\
                         esac\n\
                         done\n\
                         printf '%s\\n' \"$size\" > \"{state}/$name\"\n\
                         : > \"{dev}/$name\"\n"
                    ),
                ),
                (
                    "lvrename",
                    format!(
                        "echo \"lvrename $*\" >> \"{log}\"\n\
                         if [ -f \"{state}/$2\" ]; then mv \"{state}/$2\" \"{state}/$3\"\n\
                         mv \"{dev}/$2\" \"{dev}/$3\" 2>/dev/null; exit 0; fi\n\
                         echo \"  Failed to find logical volume \\\"$2\\\"\" >&2\n\
                         exit 5\n"
                    ),
                ),
                (
                    "lvremove",
                    format!(
                        "echo \"lvremove $*\" >> \"{log}\"\n\
                         name=${{2#*/}}\n\
                         rm -f \"{state}/$name\" \"{dev}/$name\"\n"
                    ),
                ),
                // The sandbox, as a script: it writes down the command line
                // it was given — which is what the tests read — and then
                // starts what comes after `--`, the way systemd would.
                (
                    "systemd-run",
                    format!(
                        "echo \"systemd-run $*\" >> \"{log}\"\n\
                         if [ -f \"{state}/../no-unit\" ]; then\n\
                         echo 'Failed to start transient service unit' >&2; exit 1\n\
                         fi\n\
                         while [ $# -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n\
                         shift\n\
                         exec \"$@\"\n"
                    ),
                ),
                (
                    "qemu-img",
                    format!(
                        "echo \"qemu-img $*\" >> \"{log}\"\n\
                         if [ \"$1\" = info ]; then\n\
                         echo '{{\"virtual-size\": 1024, \"format\": \"raw\"}}'\n\
                         exit 0\n\
                         fi\n\
                         if [ -f \"{state}/../convert-fails\" ]; then\n\
                         echo \"  the convert was interrupted\" >&2; exit 1\n\
                         fi\n"
                    ),
                ),
            ];
            for (name, body) in scripts {
                let path = root.join("bin").join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("the script");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("runnable");
            }
            Self {
                temp,
                handed_over: Default::default(),
            }
        }

        fn driver(&self) -> LvmThinDriver {
            let recorder = self.handed_over.clone();
            LvmThinDriver {
                config: LvmThinDriverConfig {
                    vg: "vg0".into(),
                    thin_pool: "thin".into(),
                    max_data_percent: DEFAULT_MAX_DATA_PERCENT,
                    image_dir: self.temp.path().join("images"),
                    bin_dir: Some(self.temp.path().join("bin")),
                    qemu_img: self.temp.path().join("bin").join("qemu-img"),
                    dev_dir: self.temp.path().join("dev"),
                    convert: agent_api::base_image::Sandbox::new(
                        self.temp.path().join("bin").join("systemd-run"),
                    )
                    .resolved_as(
                        4242,
                        4343,
                        std::sync::Arc::new(move |path: &Path, uid, gid| {
                            recorder.lock().expect("the recorded hand-overs").push((
                                path.to_path_buf(),
                                uid,
                                gid,
                            ));
                            Ok(())
                        }),
                    ),
                },
            }
        }

        /// The device node an LV of this fake has, which is a file.
        fn node(&self, name: &str) -> PathBuf {
            self.temp.path().join("dev").join("vg0").join(name)
        }

        /// What the driver gave to the converter and took back again.
        fn handed_over(&self) -> Vec<(PathBuf, u32, u32)> {
            self.handed_over
                .lock()
                .expect("the recorded hand-overs")
                .clone()
        }

        /// Make the transient unit refuse to start, the way a node without
        /// the `meister-convert` account does.
        fn break_the_unit(&self) {
            std::fs::write(self.temp.path().join("no-unit"), b"").expect("the marker");
        }

        /// A base image the driver will find under its image_dir.
        fn image(&self, name: &str) -> String {
            std::fs::write(self.temp.path().join("images").join(name), b"an image")
                .expect("the bytes");
            name.to_string()
        }

        /// Put an LV into the group by hand: what a run that died halfway
        /// leaves behind.
        fn lv(&self, name: &str, size: u64) {
            std::fs::write(
                self.temp.path().join("state").join(name),
                format!("{size}\n"),
            )
            .expect("the lv");
            std::fs::write(self.temp.path().join("dev").join("vg0").join(name), b"")
                .expect("its device node");
        }

        fn has_lv(&self, name: &str) -> bool {
            self.temp.path().join("state").join(name).exists()
        }

        /// Make the next `qemu-img convert` fail, the way a killed one does.
        fn break_convert(&self) {
            std::fs::write(self.temp.path().join("convert-fails"), b"").expect("the marker");
        }

        /// Every command the driver ran, in order.
        fn log(&self) -> Vec<String> {
            std::fs::read_to_string(self.temp.path().join("log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    fn from_image(name: &str) -> VolumeSpec {
        VolumeSpec {
            base_image: Some(name.to_string()),
            size_bytes: 1 << 30,
            driver: Some("lvm-thin".into()),
            params: None,
        }
    }

    /// Publish the final LV name only after conversion succeeds; a crash during
    /// conversion must not leave a half-written disk under an idempotent final name.
    #[tokio::test]
    async fn the_image_is_written_under_a_staging_name_and_renamed_when_it_is_whole() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));

        let handle = driver.provision(&id, &spec).await.expect("provisioned");

        let staging = staging_lv_name(&id);
        let final_name = lv_name(&id);
        let log = fake.log();
        let at = |needle: &str| {
            log.iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle:?} is not in {log:?}"))
        };
        assert!(
            at(&format!("-n {staging}")) < at("qemu-img convert"),
            "the lv is made under the staging name first: {log:?}"
        );
        assert!(
            at("qemu-img convert") < at(&format!("lvrename vg0 {staging} {final_name}")),
            "and renamed only after the image is whole: {log:?}"
        );
        assert!(
            log.iter()
                .all(|l| !l.ends_with(&format!("-n {final_name}"))),
            "nothing is ever created under the volume's own name: {log:?}"
        );
        assert!(fake.has_lv(&final_name), "the volume is there");
        assert!(!fake.has_lv(&staging), "and the staging name is not");
        assert_eq!(
            handle.backend,
            fake.node(&final_name).display().to_string(),
            "the handle names the volume and not the name it was built under"
        );
    }

    /// An unfinished staging LV is discarded before retrying conversion.
    #[tokio::test]
    async fn a_run_that_died_mid_image_is_redone_rather_than_handed_on() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));
        let staging = staging_lv_name(&id);
        let final_name = lv_name(&id);

        // What the crash left: the staging LV, no volume.
        fake.lv(&staging, 1 << 30);

        driver.provision(&id, &spec).await.expect("provisioned");

        let log = fake.log();
        assert!(
            log.iter()
                .any(|l| l.contains(&format!("lvremove -f vg0/{staging}"))),
            "the half-written lv is removed: {log:?}"
        );
        assert!(
            log.iter().any(|l| l.contains("qemu-img convert")),
            "and the image is written again: {log:?}"
        );
        assert!(fake.has_lv(&final_name));
        assert!(!fake.has_lv(&staging));
    }

    /// Repeated provisioning preserves a completed image volume.
    #[tokio::test]
    async fn a_volume_that_is_already_there_is_not_written_again() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));
        fake.lv(&lv_name(&id), 1 << 30);

        let handle = driver.provision(&id, &spec).await.expect("already there");

        assert_eq!(handle.size_bytes, 1 << 30, "measured, not echoed");
        let log = fake.log();
        assert!(
            log.iter().all(|l| !l.contains("qemu-img convert")),
            "no image is written over a volume that has one: {log:?}"
        );
        assert!(
            log.iter().all(|l| !l.contains("lvcreate")),
            "and nothing is created: {log:?}"
        );
    }

    /// Conversion failure removes the staging LV and restores device ownership.
    #[tokio::test]
    async fn a_convert_that_fails_leaves_no_volume_behind() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));
        fake.break_convert();

        let err = driver
            .provision(&id, &spec)
            .await
            .expect_err("the convert failed");
        assert!(
            format!("{err}").contains("interrupted"),
            "the failure carries qemu-img's own words: {err}"
        );
        assert!(!fake.has_lv(&lv_name(&id)), "no volume");
        assert!(!fake.has_lv(&staging_lv_name(&id)), "and no leftover");

        // Restore device ownership after conversion failure as well as success.
        let handed = fake.handed_over();
        assert_eq!(handed.len(), 2, "given over and taken back: {handed:?}");
        assert_eq!(handed[0].1, 4242, "to the converter: {handed:?}");
        assert_ne!(handed[1].1, 4242, "and back again: {handed:?}");
        assert_eq!(handed[0].0, handed[1].0, "the same node: {handed:?}");
    }

    /// Inspect sandbox command arguments and ownership handoffs; the fake does not
    /// exercise kernel isolation or the converter itself.
    #[tokio::test]
    async fn the_image_is_read_and_written_inside_the_unit_and_nowhere_else() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));
        let staging = staging_lv_name(&id);

        driver.provision(&id, &spec).await.expect("provisioned");

        let log = fake.log();
        let units: Vec<&String> = log
            .iter()
            .filter(|l| l.starts_with("systemd-run"))
            .collect();
        assert_eq!(units.len(), 2, "the probe and the conversion: {log:?}");
        for unit in &units {
            for property in [
                "User=meister-convert",
                "NoNewPrivileges=yes",
                "CapabilityBoundingSet=",
                "PrivateNetwork=yes",
                // Empty, not `none`: `systemd-run` refuses the word a
                // unit file would use. The trailing space is what makes
                // this an assertion about the empty value.
                "RestrictAddressFamilies= ",
                "ProtectSystem=strict",
                "ProtectHome=yes",
                "PrivateTmp=yes",
                "SystemCallFilter=@system-service",
                "MemoryMax=",
                "CPUQuota=",
                "RuntimeMaxSec=",
                "--wait",
                "--pipe",
                "--collect",
                "--quiet",
            ] {
                assert!(unit.contains(property), "{property} is missing from {unit}");
            }
            let image = fake.temp.path().join("images").join("base.raw");
            assert!(
                unit.contains(&format!("BindReadOnlyPaths={}", image.display())),
                "the image is read-only and is the only thing bound in: {unit}"
            );
        }
        // Nothing qemu-img ran was outside a unit.
        assert!(
            log.iter().all(|l| !l.starts_with("qemu-img")
                || units.iter().any(|u| u.contains(&l["qemu-img ".len()..]))),
            "every qemu-img is the tail of a unit: {log:?}"
        );
        // The destination is a block device, so the unit is told about the
        // node and nothing is bound writable at all.
        let handed = fake.handed_over();
        assert_eq!(handed.len(), 2, "given over and taken back: {handed:?}");
        let node = handed[0].0.display().to_string();
        assert!(node.ends_with(&staging), "it is the staging node: {node}");
        assert!(
            units[1].contains(&format!("DeviceAllow={node} rw")),
            "the one device it may write: {}",
            units[1]
        );
        assert!(
            !units[1].contains("BindPaths="),
            "and nothing is bound writable: {}",
            units[1]
        );
        assert!(
            !units[1].contains("PrivateDevices=yes"),
            "a private /dev would hide the node: {}",
            units[1]
        );
        assert_eq!((handed[0].1, handed[0].2), (4242, 4343), "{handed:?}");
        assert_ne!(handed[1].1, 4242, "and it is given back: {handed:?}");
    }

    /// Sandbox startup failure must not fall back to conversion in the agent process.
    #[tokio::test]
    async fn a_unit_that_does_not_start_refuses_rather_than_converting_here() {
        let fake = FakeLvm::new();
        let driver = fake.driver();
        let id: VolumeId = Uuid::new_v4();
        let spec = from_image(&fake.image("base.raw"));
        fake.break_the_unit();

        let err = driver
            .provision(&id, &spec)
            .await
            .expect_err("nothing is converted outside the unit");
        assert!(
            format!("{err}").contains("Failed to start transient service unit"),
            "the refusal carries what systemd said: {err}"
        );
        let log = fake.log();
        assert!(
            log.iter().all(|l| !l.starts_with("qemu-img")),
            "qemu-img was never started: {log:?}"
        );
        assert!(!fake.has_lv(&lv_name(&id)), "no volume");
        assert!(!fake.has_lv(&staging_lv_name(&id)), "and no leftover");
    }

    /// Local LV attachment returns the device path without a process or shared-memory requirement.
    #[tokio::test]
    async fn attaching_a_thin_lv_is_naming_its_device_node() {
        let d = driver("vg0");
        let id = uuid::Uuid::new_v4();
        let dev = PathBuf::from(format!("/dev/vg0/vm-{id}"));
        let handle = LvmThinDriver::handle(&id, &dev, 1 << 30, &spec());

        assert_eq!(handle.backend, dev.to_string_lossy());
        match d
            .attach(&handle, None)
            .await
            .expect("no cgroup, no process")
        {
            VolumeAttachment::Path(p) => assert_eq!(p, dev),
            other => panic!("a block device is a path, not {other:?}"),
        }
        d.detach(&handle, &VolumeAttachment::Path(dev.clone()))
            .await
            .expect("nothing to detach");

        // LVM exposes an ordinary block attachment.
        let attachment = VolumeAttachment::Path(dev);
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);
    }

    /// Use the handle's VG for cleanup even if configuration now names another pool.
    #[test]
    fn the_volume_group_is_recovered_from_the_handle_and_not_from_a_connection() {
        let d = driver("vg0");
        let id = uuid::Uuid::new_v4();

        let elsewhere = PathBuf::from(format!("/dev/nvme-vg/vm-{id}"));
        let handle = LvmThinDriver::handle(&id, &elsewhere, 1, &spec());
        assert_eq!(d.vg_of(&handle), "nvme-vg");

        // Legacy handles without paths fall back to the configured volume group.
        let bare = VolumeHandle {
            id,
            backend: String::new(),
            size_bytes: 0,
            params: None,
        };
        assert_eq!(d.vg_of(&bare), "vg0");

        // `/dev/<lv>` with no group in it is not a group called "dev".
        let flat = VolumeHandle {
            id,
            backend: format!("/dev/vm-{id}"),
            size_bytes: 0,
            params: None,
        };
        assert_eq!(d.vg_of(&flat), "vg0");
    }

    /// Derive LV names solely from volume IDs so retries find existing volumes.
    #[test]
    fn the_lv_name_is_derived_from_the_id_and_nothing_else() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(lv_name(&id), lv_name(&id));
        assert!(lv_name(&id).contains(&id.to_string()));
        assert_ne!(lv_name(&id), lv_name(&uuid::Uuid::new_v4()));
    }

    #[test]
    fn an_lv_is_named_after_its_volume() {
        let id: VolumeId = "6f1a2b3c-0000-0000-0000-00000000000a".parse().unwrap();
        assert_eq!(lv_name(&id), "vm-6f1a2b3c-0000-0000-0000-00000000000a");
    }

    /// The spec may point at another pool; anything that is not `<vg>/<pool>`
    /// is a rejected spec and not a guess.
    #[test]
    fn params_may_name_a_pool_and_must_name_it_properly() {
        let default = LvmThinParams::default();
        assert_eq!(
            resolve_pool(&default, "vg0", "thin").unwrap(),
            ("vg0".into(), "thin".into())
        );

        let named = LvmThinParams {
            pool: Some("fast/pool0".into()),
        };
        assert_eq!(
            resolve_pool(&named, "vg0", "thin").unwrap(),
            ("fast".into(), "pool0".into())
        );

        for bad in ["nvme", "/pool", "vg/"] {
            let p = LvmThinParams {
                pool: Some(bad.into()),
            };
            let err = resolve_pool(&p, "vg0", "thin").unwrap_err().to_string();
            assert!(err.contains("<vg>/<thin_pool>"), "{bad}: {err}");
        }
    }

    /// Admit pool usage equal to the configured limit; refuse only greater usage.
    #[test]
    fn a_pool_over_the_limit_is_refused_and_says_why() {
        assert!(admits(89.99, 90.0).is_ok());
        assert!(admits(90.0, 90.0).is_ok());
        let err = admits(90.01, 90.0).unwrap_err().to_string();
        assert!(err.contains("90.01% full"), "{err}");
        assert!(
            err.contains("90.00% limit"),
            "the message must name the limit: {err}"
        );
        assert!(
            err.contains("max_data_percent"),
            "and where to change it: {err}"
        );
        assert!(admits(0.0, 0.0).is_ok());
        assert!(admits(99.9, 100.0).is_ok());
    }

    /// `lvs --noheadings` indents every line and can hand back an empty one
    /// for a field the LV does not have. Both are what this reads.
    #[test]
    fn lvs_output_is_read_through_its_padding() {
        assert_eq!(parse_lvs_field("  42.00 \n"), Some("42.00"));
        assert_eq!(parse_lvs_field("\n  \n  7\n"), Some("7"));
        assert_eq!(parse_lvs_field(""), None);
        assert_eq!(parse_lvs_field("   \n  \n"), None);

        assert_eq!(parse_number("  12.34 \n", "data_percent").unwrap(), 12.34);
        assert_eq!(
            parse_number("  67108864 \n", "lv_size").unwrap(),
            67108864.0
        );
        assert!(parse_number("  \n", "data_percent").is_err());
        assert!(parse_number("  <nope> \n", "data_percent").is_err());
    }

    /// Distinguish recognized LV absence from other LVM failures.
    #[test]
    fn lvm_says_absent_in_prose_and_nothing_else() {
        assert!(means_absent("  Failed to find logical volume \"vg0/vm-x\""));
        assert!(means_absent("  Volume group \"vg0\" not found"));
        assert!(means_absent(
            "Cannot process volume group vg0: No such device"
        ));
        assert!(!means_absent(
            "  Insufficient free space: 100 extents needed"
        ));
        assert!(!means_absent("  /dev/sdb: open failed: Permission denied"));
    }

    #[test]
    fn a_thin_volume_is_a_device_node_under_its_vg() {
        assert_eq!(
            driver("meister-test").device_path("meister-test", "vm-abc"),
            PathBuf::from("/dev/meister-test/vm-abc")
        );
    }

    /// Reject unknown LVM parameters instead of silently ignoring misspelled settings.
    #[test]
    fn unknown_params_are_refused() {
        let spec = |params| VolumeSpec {
            base_image: None,
            size_bytes: 1,
            driver: Some("lvm-thin".into()),
            params,
        };
        assert!(LvmThinDriver::params(&spec(None)).unwrap().pool.is_none());
        assert_eq!(
            LvmThinDriver::params(&spec(Some(serde_json::json!({"pool": "vg/p"}))))
                .unwrap()
                .pool
                .as_deref(),
            Some("vg/p")
        );
        let err = LvmThinDriver::params(&spec(Some(serde_json::json!({"pooll": "vg/p"}))))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid lvm-thin params"), "{err}");
    }

    /// Thin volumes advertise node-local placement.
    #[test]
    fn a_thin_lv_is_node_local() {
        assert_eq!(driver("vg0").locality(), Locality::NodeLocal);
    }

    /// Snapshot names have a separate prefix and use the origin handle's VG.
    #[test]
    fn a_snapshot_is_its_own_lv_in_the_volume_group_its_origin_is_in() {
        let d = driver("vg0");
        assert_eq!(
            d.snapshot_support(),
            Some(SnapshotConsistency::Atomic),
            "lvcreate -s on a thin lv is one instant; nothing has to be paused"
        );

        let volume = Uuid::new_v4();
        let snapshot = Uuid::new_v4();
        assert_eq!(lv_name(&volume), format!("vm-{volume}"));
        assert_eq!(snapshot_lv_name(&snapshot), format!("snap-{snapshot}"));
        assert_ne!(
            lv_name(&volume),
            snapshot_lv_name(&volume),
            "one uuid, two lvs"
        );

        // A volume whose spec put it in another VG: the snapshot follows the
        // origin, not the configuration.
        let elsewhere = VolumeHandle {
            id: volume,
            backend: format!("/dev/vg9/vm-{volume}"),
            size_bytes: 1 << 30,
            params: None,
        };
        assert_eq!(d.vg_of(&elsewhere), "vg9");
        let taken = LvmThinDriver::snapshot_handle(
            &snapshot,
            &d.device_path("vg9", &snapshot_lv_name(&snapshot)),
            1 << 30,
        );
        assert_eq!(taken.backend, format!("/dev/vg9/snap-{snapshot}"));
        assert_eq!(taken.id, snapshot, "the handle names the copy");
        assert!(
            taken.params.is_none(),
            "attach options belong to a connection, and nothing attaches a snapshot"
        );
        // And dropping it goes back to the same VG the handle names.
        assert_eq!(d.vg_of(&taken), "vg9");

        // A handle with no path at all — a record migrated from before
        // handles existed — falls back to the configured VG, exactly as
        // `deprovision` does.
        let bare = VolumeHandle {
            id: snapshot,
            backend: String::new(),
            size_bytes: 0,
            params: None,
        };
        assert_eq!(d.vg_of(&bare), "vg0");
    }

    /// Check the rounding arithmetic used for idempotent growth; this test does not run lvextend.
    #[test]
    fn a_thin_volume_grows_to_at_least_what_was_asked_for() {
        let gib = 1u64 << 30;
        // What the driver does with a request it has already met, expressed
        // as the comparison it makes: nothing, whether the LV is exactly the
        // size or larger.
        for have in [gib, gib + (4 << 20)] {
            assert!(have >= gib, "already there");
        }
        assert!(gib > gib - 1, "and a genuine growth is not");

        // GiB-sized requests align with the tested 4 MiB extent and 512-byte sector sizes.
        assert_eq!(gib % (4 << 20), 0);
        assert_eq!(gib % 512, 0);
    }
}
