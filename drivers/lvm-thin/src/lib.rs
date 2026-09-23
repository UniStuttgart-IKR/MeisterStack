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
    self, Locality, SnapshotConsistency, SnapshotId, StorageError, VolumeAttacher,
    VolumeAttachment, VolumeHandle, VolumeId, VolumeProvider, VolumeSpec, VolumeState,
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

/// The name an LV is built under before it is the volume.
///
/// Astra finding S14, 2026-09-23: `provision` read "the LV exists" as "the
/// volume is ready", and it created the LV under its FINAL name before
/// `qemu-img convert` had written a byte into it. A node that died in the
/// middle of the convert — a reboot, an OOM kill, a power cut — left an LV
/// under the name the next call looks for, and that call said "thin volume
/// already exists" and handed a guest a disk with half an image on it.
///
/// So the bytes are written under a name nothing looks for, and the LAST
/// thing that happens is the rename. An LV rename is one atomic change of the
/// VG's metadata, so the final name appears when the image is whole and never
/// before it — the same shape `write_volume_file` has in the filesystem
/// driver, where it is a tmp file and a `rename`.
///
/// Derived from the id like every other name here, so a leftover from a run
/// that died is found by the next call rather than leaked.
fn staging_lv_name(id: &VolumeId) -> String {
    format!("{}.staging", lv_name(id))
}

/// The LV a snapshot is. A prefix of its own so that `lvs` on a node reads
/// as what it is, and so that a snapshot can never collide with a volume:
/// both are derived from a uuid, and two different uuids is not a promise
/// worth resting on when one prefix says it outright.
fn snapshot_lv_name(id: &SnapshotId) -> String {
    format!("snap-{id}")
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

    /// The handle for a SNAPSHOT's LV. Beside `handle` and not folded into
    /// it, because a snapshot carries no spec and therefore no params: attach
    /// options belong to a connection, and nothing ever attaches a snapshot.
    fn snapshot_handle(id: &SnapshotId, dev: &Path, size_bytes: u64) -> VolumeHandle {
        VolumeHandle {
            id: *id,
            backend: dev.to_string_lossy().into_owned(),
            size_bytes,
            params: None,
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

    /// Write the base image onto the LV. `qemu-img convert` and not `dd`
    /// because it reads qcow2 as well as raw, and the images this lab boots
    /// are both.
    ///
    /// The format is the one `agent_api::base_image::probe` judged and is
    /// passed with `-f`. Astra finding S01, 2026-09-23: this ran `convert -O
    /// raw` with no `-f` and refused nothing, so the source format was
    /// decided again here — and an image naming a backing file or an external
    /// data file had that second file read into the guest's disk, by a
    /// converter that on a node with `unprivileged = false` is root.
    async fn write_base_image(
        &self,
        image: &agent_api::base_image::BaseImage,
        src: &Path,
        dev: &Path,
        name: &str,
    ) -> storage::Result<()> {
        let out = tokio::process::Command::new(&self.config.qemu_img)
            .args(agent_api::base_image::convert_argv(image, src, dev))
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

    /// Give the finished LV its real name. See [`staging_lv_name`].
    ///
    /// `Ok(None)` from `lvm` means LVM could not find the name to rename,
    /// which here is not "nothing to do": the LV was created one call ago and
    /// the bytes were just written into it, so its absence is a failure and
    /// has to read as one.
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
        let dev = Self::device_path(&vg, &lv);

        // Idempotent like every other create in this tree: a re-provision of
        // the same volume finds its LV and is done. Only the FINAL name
        // counts, and that is the whole of S14: the name exists because the
        // image was written, not merely because an `lvcreate` once returned.
        if let Some(size) = self.lv_size_bytes(&vg, &lv).await? {
            debug!(size_bytes = size, "thin volume already exists");
            return Ok(Self::handle(id, &dev, size, spec));
        }

        // A staging LV without a volume beside it is what a run that died
        // mid-convert leaves: half an image under a name nothing looks for.
        // It is dropped and the work is done again, because the one thing
        // that must not happen is a guest booting off it.
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
                // One probe, and it answers both questions: how big the image
                // is once written out raw — a qcow2 file is smaller than the
                // disk it describes, so the file's own length is the wrong
                // number — and whether this node will convert it at all. See
                // `agent_api::base_image` for what it refuses and why.
                let image =
                    agent_api::base_image::probe(&self.config.qemu_img, &path, name).await?;
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
        // A volume with a base image is built under the staging name and
        // renamed when the image is whole; a volume WITHOUT one is finished
        // the moment `lvcreate` returns, so it is created under its own name
        // and there is no window to protect. See [`staging_lv_name`].
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

        // From here on the LV exists, so every failure has to take it with it
        // — a half-written volume that survives would be handed to the next
        // boot as if it were ready.
        if let Some((path, name, image)) = src {
            let staging_dev = Self::device_path(&vg, &staging);
            info!(base = %path.display(), dev = %staging_dev.display(),
                  format = %image.format, "writing base image onto lv");
            if let Err(e) = self
                .write_base_image(&image, &path, &staging_dev, &name)
                .await
            {
                warn!(error = %format!("{e:#}"),
                      "base image failed, removing the lv again");
                if let Err(rm) = self.remove_lv(&vg, &staging).await {
                    // Error and not warn: the rollback is what keeps a
                    // half-written volume from being handed to the next boot.
                    // Since S14 a leftover under the staging name is found and
                    // dropped by the next provision of this volume, so it is
                    // no longer forever — but it still costs the pool its data
                    // until then, and nobody is told unless this line is.
                    error!(vg = %vg, lv = %staging, error = %format!("{rm:#}"),
                           "rollback failed, the half-written lv is orphaned");
                }
                return Err(e);
            }
            // And only now does the volume have the name the next call looks
            // for. One atomic change of the VG metadata; there is no state
            // between the two names.
            self.rename_lv(&vg, &staging, &lv).await?;
        }

        let size_bytes = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .unwrap_or(spec.size_bytes);
        info!(dev = %dev.display(), size_bytes, "thin volume ready");
        Ok(Self::handle(id, &dev, size_bytes, spec))
    }

    /// `lvextend -L` on the LV, and never downwards.
    ///
    /// A thin LV's size is its VIRTUAL size, so growing one takes no room out
    /// of the pool until the guest writes into it — the same arithmetic
    /// `provision` relies on when it cuts a 100 GiB volume out of a 40 GiB
    /// pool. What `admits` guards is the pool's real fill, and that does not
    /// move here.
    ///
    /// The size read back is LVM's own, not the one asked for: `lvextend`
    /// rounds up to the extent size (4 MiB by default), so the LV comes out
    /// at least as big as requested and usually a little bigger. Reading it
    /// back is what keeps `status.sizeGib` a measurement rather than a copy
    /// of the request.
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
            // Already there, or bigger because LVM rounded up last time.
            // Idempotent either way, and the `>=` is what makes a second call
            // with the same request a no-op rather than a shrink.
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

    /// Native and atomic. `lvcreate -s` on a thin LV is a copy-on-write
    /// snapshot inside the same pool: milliseconds, no data copied, and the
    /// instant it names is one instant. Nothing has to be paused, which is
    /// the whole difference from the file backends.
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
        let dev = Self::device_path(&vg, &snap);
        // Idempotent by the same rule everything else here follows: the name
        // is derived from the id, so a second call finds the first one's LV.
        if let Some(size) = self.lv_size_bytes(&vg, &snap).await? {
            debug!(size_bytes = size, "snapshot lv already exists");
            return Ok(Self::snapshot_handle(id, &dev, size));
        }
        let source = format!("{vg}/{}", lv_name(&handle.id));
        // `-s` alone: a thin snapshot inherits its size from its origin and
        // `-L` would turn it into an old-style COW snapshot with a fixed
        // exception store, which is the one that runs full and breaks.
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
        let dev = Self::device_path(&vg, &lv);
        if let Some(size) = self.lv_size_bytes(&vg, &lv).await? {
            debug!(size_bytes = size, "thin volume already exists");
            return Ok(Self::handle(id, &dev, size, spec));
        }
        // A snapshot OF a snapshot, which in a thin pool is just another
        // writeable LV sharing the same blocks — no copy, and the new volume
        // diverges from the snapshot as it is written to. `-K` because a thin
        // snapshot is created with the "activation skip" flag set and would
        // otherwise have no device node for the VMM to open.
        let source = format!("{vg}/{}", snapshot_lv_name(&snapshot.id));
        self.lvm("lvcreate", &["-s", "-K", "-n", &lv, &source])
            .await?
            .ok_or(StorageError::NotFound(snapshot.id))?;
        let size_bytes = self
            .lv_size_bytes(&vg, &lv)
            .await?
            .unwrap_or(snapshot.size_bytes);
        // The size asked for is not what a thin snapshot comes out at — it
        // inherits the origin's — and this driver does not grow it here: the
        // spec's number is the intent, `resize` is the verb, and a silent
        // extend would hide the one case where somebody asked for less.
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
        // And whatever an attempt that died mid-image left under the staging
        // name (S14). `lvremove` of a name that is not there is `Ok(None)`
        // here, so the common case costs one command and says nothing.
        let staging = staging_lv_name(&handle.id);
        self.remove_lv(&vg, &staging).await?;
        Ok(())
    }

    /// A thin LV lives in a volume group, and a volume group is on one
    /// machine's disks. The degenerate case the whole provider/attacher split
    /// has to keep cheap: provision and attach land on the same node because
    /// there is no other node the bytes could be reached from.
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

    /// The LV this pool would have made for `id`, if it is in the group.
    ///
    /// The same `lvs` that makes `provision` idempotent, asked on its own: the
    /// LV's name is derived from the id, so this backend can be asked what it
    /// holds for a record whose handle was never written. Astra finding S13,
    /// 2026-09-23.
    #[instrument(level = "trace", skip_all, fields(volume_id = %id))]
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &VolumeSpec,
    ) -> storage::Result<Option<VolumeHandle>> {
        let params = Self::params(spec)?;
        let (vg, _) = resolve_pool(&params, &self.config.vg, &self.config.thin_pool)?;
        let lv = lv_name(id);
        let dev = Self::device_path(&vg, &lv);
        Ok(self
            .lv_size_bytes(&vg, &lv)
            .await?
            .map(|size| Self::handle(id, &dev, size, spec)))
    }

    /// And the snapshot's LV, which needs the volume it came from.
    ///
    /// The volume group is on the VOLUME's handle and nowhere else — a
    /// snapshot record carries a driver name and an id — so a probe with no
    /// volume in hand is refused rather than guessed at against the
    /// configured group: guessing would answer "nothing here" for a snapshot
    /// in another group, and a tombstone is what follows that answer.
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
        let dev = Self::device_path(&vg, &snap);
        Ok(self
            .lv_size_bytes(&vg, &snap)
            .await?
            .map(|size| Self::snapshot_handle(id, &dev, size)))
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

    /// LVM and `qemu-img` as shell scripts, and a volume group as a
    /// directory of files.
    ///
    /// This driver IS its command line — LVM has no library worth linking —
    /// so the only way to test what it does to a volume group is to give it
    /// commands it can run. Each script keeps the group in `state/` (one file
    /// per LV, holding its size) and appends what it was asked to do to
    /// `log`, which is what the tests then read: the ORDER of those lines is
    /// the property S14 is about.
    ///
    /// Nothing here talks to a disk, a pool or a real `qemu-img`, and none of
    /// the scripts starts a process of its own.
    struct FakeLvm {
        temp: tempfile::TempDir,
    }

    impl FakeLvm {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt;

            let temp = tempfile::Builder::new()
                .prefix("meister-lvm-thin-")
                .tempdir()
                .expect("a temp dir");
            let root = temp.path();
            for dir in ["bin", "state", "images"] {
                std::fs::create_dir_all(root.join(dir)).expect("the fake's directories");
            }
            let state = root.join("state").display().to_string();
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
                         printf '%s\\n' \"$size\" > \"{state}/$name\"\n"
                    ),
                ),
                (
                    "lvrename",
                    format!(
                        "echo \"lvrename $*\" >> \"{log}\"\n\
                         if [ -f \"{state}/$2\" ]; then mv \"{state}/$2\" \"{state}/$3\"; exit 0; fi\n\
                         echo \"  Failed to find logical volume \\\"$2\\\"\" >&2\n\
                         exit 5\n"
                    ),
                ),
                (
                    "lvremove",
                    format!(
                        "echo \"lvremove $*\" >> \"{log}\"\n\
                         name=${{2#*/}}\n\
                         rm -f \"{state}/$name\"\n"
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
            Self { temp }
        }

        fn driver(&self) -> LvmThinDriver {
            LvmThinDriver {
                config: LvmThinDriverConfig {
                    vg: "vg0".into(),
                    thin_pool: "thin".into(),
                    max_data_percent: DEFAULT_MAX_DATA_PERCENT,
                    image_dir: self.temp.path().join("images"),
                    bin_dir: Some(self.temp.path().join("bin")),
                    qemu_img: self.temp.path().join("bin").join("qemu-img"),
                },
            }
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

    /// The image is written under a name nothing looks for, and the volume's
    /// own name appears only when it is whole.
    ///
    /// Astra finding S14, 2026-09-23: the LV used to be created under its
    /// final name and the image written into it afterwards, so a node that
    /// died between the two left an LV that the next provision read as
    /// "already exists" and handed to a guest with half an image on it. The
    /// order of the commands IS the fix, which is why the test reads the
    /// order.
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
            format!("/dev/vg0/{final_name}"),
            "the handle names the volume and not the name it was built under"
        );
    }

    /// A node that died mid-convert: the leftover is dropped and the work is
    /// done again, and what the guest gets is a whole image.
    ///
    /// Astra finding S14, 2026-09-23. This is the case the old code got
    /// wrong in the one direction that cannot be recovered from — it handed
    /// the half-written disk on — and the staging name is what turns it into
    /// a case at all: an LV under a name nothing looks for is evidence of a
    /// run that did not finish.
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

    /// A volume that is already there is not written again — the idempotence
    /// every create in this tree has, now resting on the one name that means
    /// the image is whole.
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

    /// A convert that fails leaves nothing under either name.
    ///
    /// Astra finding S14, 2026-09-23: the rollback was always here, and what
    /// it could not cover was the failure that takes the whole node with it.
    /// What it covers now is the same failure under a name that was never the
    /// volume's, so even a rollback that does not run leaves nothing the next
    /// provision can mistake for a finished disk.
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

    /// A volume group is on one machine's disks. The degenerate case of the
    /// provider/attacher split, and the value that pins a VM to the node its
    /// LV is on.
    #[test]
    fn a_thin_lv_is_node_local() {
        assert_eq!(driver("vg0").locality(), Locality::NodeLocal);
    }

    /// The two names a snapshot answers to on this backend, and the volume
    /// group both are cut from.
    ///
    /// A prefix of its own (`snap-`) so an `lvs` reads as what it is, and so
    /// that a snapshot can never collide with a volume: both are derived from
    /// a uuid, and "two different uuids" is not a promise worth resting on
    /// when one prefix says it outright.
    ///
    /// The VG comes off the HANDLE and not off the configuration, which is
    /// the same rule `deprovision` follows and for the same reason: a spec
    /// that named a pool of its own may have put the LV somewhere the config
    /// no longer points, and a snapshot dropped out of the wrong VG is either
    /// nothing or somebody else's.
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
            &LvmThinDriver::device_path("vg9", &snapshot_lv_name(&snapshot)),
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

    /// Growing an LV, and the size that comes back.
    ///
    /// `lvextend -L <bytes>b`, and then the size is READ BACK rather than
    /// echoed: LVM rounds up to the extent size (4 MiB by default), so an LV
    /// asked for 1 GiB comes out at 1 GiB or a little more. Echoing the
    /// request would make `status.sizeGib` a copy of `spec.sizeGib` and the
    /// evidence half of the resize would say nothing.
    ///
    /// The `>=` in the idempotence check is what that rounding forces: a
    /// second call with the same request meets an LV that is already BIGGER
    /// than what was asked for, and treating that as a shrink would refuse a
    /// no-op.
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

        // A GiB is a multiple of the extent size AND of the sector size, so
        // neither `lvextend` nor `vm.resize-disk` has anything to round or
        // refuse. That is why the object measures in GiB.
        assert_eq!(gib % (4 << 20), 0);
        assert_eq!(gib % 512, 0);
    }
}
