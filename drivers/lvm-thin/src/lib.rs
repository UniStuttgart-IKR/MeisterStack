// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Block driver over an LVM thin pool: one thin LV per volume, on real
//! block storage, local to the node.
//!
//! Everything here is `lvcreate`/`lvs`/`lvremove` — LVM has no library worth
//! linking and its command line is its API, so the driver is a thin, honest
//! wrapper around three commands plus `qemu-img` for the base image. The
//! parsing that results is what the unit tests below are about: the shape of
//! `lvs --noheadings` output is the one thing that can silently change under
//! us, and a misread `data_percent` would turn admission into a coin flip.
//!
//! The volume reaches the VMM as `Path("/dev/<vg>/<lv>")` — a block device
//! cloud-hypervisor opens itself. No backend process, so no cgroup and
//! nothing to keep alive.

use std::path::{Path, PathBuf};

use agent_api::CgroupHandle;
use agent_api::storage::{
    self, StorageError, VolumeAttacher, VolumeAttachment, VolumeHandle, VolumeId, VolumeProvider,
    VolumeSpec, VolumeState,
};
use tracing::{debug, error, info, instrument, warn};

/// The default admission limit, in percent of the thin pool's data space.
/// Past this a pool is close enough to full that the next guest write is the
/// one that wedges every VM on it, not just the new one.
pub const DEFAULT_MAX_DATA_PERCENT: f64 = 90.0;

/// Per-volume options. The one thing worth naming per volume is which pool to
/// cut the LV from — a node with a fast NVMe pool and a slow spinning one has
/// exactly this choice to offer, and the spec is where it is made.
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
    /// Where `base_image` names a file. The same directory the filesystem
    /// driver clones from — an image is an image, whatever it is written onto.
    pub image_dir: PathBuf,
    /// Where to find `lvs`/`lvcreate`/`lvremove`. None = whatever PATH says,
    /// which is right on a NixOS node and wrong nowhere in particular.
    pub bin_dir: Option<PathBuf>,
    pub qemu_img: PathBuf,
}

pub struct LvmThinDriver {
    config: LvmThinDriverConfig,
}

/// `<vg>/<lv>`, the way LVM wants a volume named on a command line.
fn lv_name(id: &VolumeId) -> String {
    format!("vm-{id}")
}

/// The pool a spec asks for: `params.pool` if it names one, the configured
/// pair otherwise. Split here rather than at the call sites so that a
/// malformed `pool` is one message and not three.
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

/// Whether a pool this full may take another volume.
///
/// The honest statement, and it is not the nvrm one: a thin pool is
/// overprovisioned on purpose, so summing what the LVs on it were *asked*
/// for would refuse every pool that is doing its job. What actually breaks a
/// thin pool is running out of data space, at which point every VM on it
/// takes I/O errors — including the ones that were there first. So the number
/// admission looks at is the pool's real fill, and the limit is the distance
/// this driver insists on keeping from the cliff.
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
        // Fail-fast at agent start, exactly as the nvrm driver resolves its
        // vGPU types there: a pool that is not on this host is a config
        // error, and finding it out at the first VM boot helps nobody.
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

    fn device_path(vg: &str, lv: &str) -> PathBuf {
        PathBuf::from(format!("/dev/{vg}/{lv}"))
    }

    /// The handle for an LV at `dev`. One place, so that `provision`'s two
    /// exits cannot describe the same volume differently.
    fn handle(id: &VolumeId, dev: &Path, size_bytes: u64, spec: &VolumeSpec) -> VolumeHandle {
        VolumeHandle {
            id: *id,
            backend: dev.to_string_lossy().into_owned(),
            size_bytes,
            params: spec.params.clone(),
        }
    }

    /// Which volume group this handle's LV is in: the parent directory of
    /// `/dev/<vg>/<lv>`, falling back to the configured one for a handle that
    /// carries no path (a record migrated from before handles existed, whose
    /// attachment was not a path).
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

    /// Run one LVM command. `Ok(None)` means the thing it was about does not
    /// exist; anything else that failed is a backend error carrying LVM's own
    /// words, which are usually the useful ones.
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

    /// The LV's real size. LVM rounds a request up to whole extents, and the
    /// record should say what the guest actually got rather than what was
    /// asked for.
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

    /// What the base image will occupy once written out raw. qcow2 files are
    /// smaller on disk than the disk they describe, so the file's own length
    /// is the wrong number to compare against — this is the right one.
    async fn image_virtual_size(&self, path: &PathBuf, name: &str) -> storage::Result<u64> {
        let out = tokio::process::Command::new(&self.config.qemu_img)
            .args(["info", "--output=json"])
            .arg(path)
            .output()
            .await
            .map_err(|e| StorageError::Backend(anyhow::anyhow!("running qemu-img info: {e}")))?;
        if !out.status.success() {
            return Err(StorageError::ImageNotFound(format!(
                "{name}: qemu-img info failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let info: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| StorageError::Backend(anyhow::anyhow!("qemu-img info json: {e}")))?;
        info.get("virtual-size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                StorageError::Backend(anyhow::anyhow!(
                    "qemu-img info for {name} has no virtual-size"
                ))
            })
    }

    /// Write the base image onto the LV. `qemu-img convert` and not `dd`
    /// because it reads qcow2 as well as raw, and the images this lab boots
    /// are both.
    async fn write_base_image(
        &self,
        src: &PathBuf,
        dev: &PathBuf,
        name: &str,
    ) -> storage::Result<()> {
        let out = tokio::process::Command::new(&self.config.qemu_img)
            .arg("convert")
            .arg("-O")
            .arg("raw")
            .arg(src)
            .arg(dev)
            .output()
            .await
            .map_err(|e| StorageError::Backend(anyhow::anyhow!("running qemu-img convert: {e}")))?;
        if !out.status.success() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "qemu-img convert {name} -> {}: {}",
                dev.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    async fn remove_lv(&self, vg: &str, lv: &str) -> storage::Result<()> {
        let target = format!("{vg}/{lv}");
        self.lvm("lvremove", &["-f", &target]).await.map(|_| ())
    }
}

#[async_trait::async_trait]
impl VolumeProvider for LvmThinDriver {
    #[instrument(skip_all, fields(volume_id = %id, size_bytes = spec.size_bytes))]
    async fn provision(&self, id: &VolumeId, spec: &VolumeSpec) -> storage::Result<VolumeHandle> {
        let params = Self::params(spec)?;
        let (vg, pool) = resolve_pool(&params, &self.config.vg, &self.config.thin_pool)?;
        let lv = lv_name(id);
        let dev = Self::device_path(&vg, &lv);

        // Idempotent like every other create in this tree: a re-provision of
        // the same volume finds its LV and is done.
        if let Some(size) = self.lv_size_bytes(&vg, &lv).await? {
            debug!(size_bytes = size, "thin volume already exists");
            return Ok(Self::handle(id, &dev, size, spec));
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
                let virtual_size = self.image_virtual_size(&path, name).await?;
                if virtual_size > spec.size_bytes {
                    return Err(StorageError::InvalidSpec(format!(
                        "size_bytes {} smaller than base image {name} ({virtual_size} bytes raw)",
                        spec.size_bytes
                    )));
                }
                Some((path, name.clone()))
            }
            None => None,
        };

        let target_pool = format!("{vg}/{pool}");
        let size_arg = format!("{}b", spec.size_bytes);
        self.lvm(
            "lvcreate",
            &["-T", &target_pool, "-V", &size_arg, "-n", &lv],
        )
        .await?
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!("thin pool {target_pool} disappeared"))
        })?;

        // From here on the LV exists, so every failure has to take it with it
        // — a half-written volume that survives would be handed to the next
        // boot as if it were ready.
        if let Some((path, name)) = src {
            info!(base = %path.display(), dev = %dev.display(), "writing base image onto lv");
            if let Err(e) = self.write_base_image(&path, &dev, &name).await {
                warn!(error = %format!("{e:#}"),
                      "base image failed, removing the lv again");
                if let Err(rm) = self.remove_lv(&vg, &lv).await {
                    // Error and not warn: the rollback is what keeps a
                    // half-written volume from being handed to the next boot,
                    // and no later pass comes back for this lv. It stays in
                    // the vg until somebody removes it.
                    error!(vg = %vg, lv = %lv, error = %format!("{rm:#}"),
                           "rollback failed, the lv is orphaned");
                }
                return Err(e);
            }
        }

        let size_bytes = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .unwrap_or(spec.size_bytes);
        info!(dev = %dev.display(), size_bytes, "thin volume ready");
        Ok(Self::handle(id, &dev, size_bytes, spec))
    }

    #[instrument(skip_all, fields(volume_id = %handle.id))]
    async fn deprovision(&self, handle: &VolumeHandle) -> storage::Result<()> {
        // The handle is where the record remembers which VG the LV was cut
        // from — a spec that named a pool of its own may have put it
        // somewhere the config no longer points. It used to be read off the
        // attachment, which is the sentence this whole split is about: the VG
        // is a property of the VOLUME, and reading it out of a connection
        // meant the data could not be deleted without one.
        let lv = lv_name(&handle.id);
        let vg = self.vg_of(handle);
        self.remove_lv(&vg, &lv).await?;
        debug!(vg = %vg, lv = %lv, "thin volume removed");
        Ok(())
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
}

/// The second degenerate case, and the plainest: a thin LV is a block device
/// the VMM opens itself. Attaching is naming the device node, detaching is
/// nothing, and no process is spawned — so no cgroup is taken.
///
/// The day this backend grows an NVMe-oF export, THIS is the impl that gets a
/// target session and a cgroup, and `VolumeProvider` above does not change a
/// line. That is what the split was for.
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

    fn driver(vg: &str) -> LvmThinDriver {
        LvmThinDriver {
            config: LvmThinDriverConfig {
                vg: vg.into(),
                thin_pool: "thin".into(),
                max_data_percent: DEFAULT_MAX_DATA_PERCENT,
                image_dir: PathBuf::from("/var/lib/meister/images"),
                bin_dir: None,
                qemu_img: PathBuf::from("qemu-img"),
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

    /// The degeneration probe for this backend, and it is the plainest of the
    /// three: a thin LV is a block device the VMM opens itself, so attaching
    /// is naming the device node and detaching is nothing.
    ///
    /// No cgroup is taken and none is offered, which is the claim that
    /// matters: `provision` and `attach` land on the same node here and the
    /// split has to cost that case nothing. The day this backend grows an
    /// NVMe-oF export, THIS impl gets a target session and a cgroup and the
    /// provider half does not change a line.
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

        // And what the VMM is told is what it was always told.
        let attachment = VolumeAttachment::Path(dev);
        assert!(attachment.is_block());
        assert!(!attachment.needs_shared_memory());
        assert_eq!(attachment.backend_pid(), None);
    }

    /// The volume group comes off the HANDLE now and used to come off the
    /// attachment. Same answer, and that is the point of the probe: a spec
    /// that named a pool of its own put the LV somewhere the config no longer
    /// points, and deprovision has to find it there with no consumer in the
    /// picture.
    #[test]
    fn the_volume_group_is_recovered_from_the_handle_and_not_from_a_connection() {
        let d = driver("vg0");
        let id = uuid::Uuid::new_v4();

        let elsewhere = PathBuf::from(format!("/dev/nvme-vg/vm-{id}"));
        let handle = LvmThinDriver::handle(&id, &elsewhere, 1, &spec());
        assert_eq!(d.vg_of(&handle), "nvme-vg");

        // A handle with no path at all — a record migrated from before
        // handles existed, whose attachment was not a path — falls back to
        // the configured group rather than to nothing.
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

    /// The name is derived from the id, on this backend as on every other.
    /// The idempotence rule stated where it actually lives: `lvcreate` for a
    /// volume that is already there is what `provision` finds, and it finds
    /// it because nothing about the name was allocated.
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

    /// Admission is the pool's real fill against the limit, and the boundary
    /// is inclusive: a pool sitting exactly on the limit is still admitted,
    /// so a limit of 100 never refuses and a limit of 0 refuses everything
    /// that has been written to at all.
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

    /// "There is no such LV" has to be told apart from "LVM is broken":
    /// the first is a NotFound and an idempotent destroy, the second is an
    /// error an operator has to see.
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
            LvmThinDriver::device_path("meister-test", "vm-abc"),
            PathBuf::from("/dev/meister-test/vm-abc")
        );
    }

    /// Unknown params are a rejected spec rather than a silently ignored
    /// option — the same trade `NvrmParams` makes, and for the same reason:
    /// a typo'd knob that is quietly dropped looks exactly like one that did
    /// not work.
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
}
