// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What runs ON the installer medium, and the one question it has to get
//! right: **is this the disk?**
//!
//! Everything else about a first installation is recoverable. A wrong
//! toplevel is a second `apply`; a missing certificate is a bootstrap; a
//! host that does not come up is a console away. A disk that was partitioned
//! by mistake is somebody's data, and there is no verb for that. So this
//! module is five refusals and one action, in that order:
//!
//! 1. the medium says which host it is for, and `--host` has to agree;
//! 2. exactly ONE disk carries the serial that was typed, and its size is
//!    the size the inventory declared;
//! 3. that disk is the device the LAYOUT names — the bridge between a
//!    serial (which a person reads off a sticker) and a
//!    `/dev/disk/by-id/...` (which depends on the transport and the model,
//!    M0 probe S7, and cannot be derived from the serial);
//! 4. no partition of it already carries an installation mark, unless
//!    `--reinstall` says so on purpose;
//! 5. nothing this host preserves lives on it.
//!
//! Only then does anything happen, and what happens is printed first.
//!
//! **Preserve means "not touched", not "copied".** This program moves no
//! data anywhere. A path in `install.preserve` that turns out to be on the
//! disk about to be formatted is a refusal, because the alternative —
//! copying it somewhere and putting it back — is a backup tool, and a
//! backup tool that only runs during an install is a backup nobody tested.
//!
//! **It reboots nothing.** The last thing it prints is what to do next, and
//! a person does it. A medium that rebooted into the machine it just
//! installed would be a medium that decides when a data centre's power draw
//! changes.
//!
//! Everything goes through [`Runner`], [`Files`] and [`Clock`], like the
//! rest of this crate, so that the command lines that destroy a partition
//! table can be read in a unit test — which is the only place they can be
//! read at all.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effects::{Clock, Files};
use crate::manifest::BootMode;
use crate::run::{Cmd, Effect, Expect, Runner};

/// What the medium was built with: which host, which disk, which system.
pub const INSTALL_TARGET_SCHEMA: &str = "meister-deploy/install-target/1";

/// What an installed disk carries so that the next medium can tell.
pub const INSTALLED_SCHEMA: &str = "meister-deploy/installed/1";

/// Where the medium keeps its answer, and where the mark goes on the
/// installed system. The same directory on both sides on purpose: a person
/// who knows one knows the other.
pub const TARGET_PATH: &str = "/etc/meister-install/target.json";
pub const MARK_PATH: &str = "etc/meister-install/installed.json";

/// Where the target is mounted while it is being installed. disko's own
/// `rootMountPoint` default, because the script this program runs is the
/// one the host's layout built and it mounts there.
pub const ROOT: &str = "/mnt";

/// Where a partition is mounted for a moment to look for the mark.
pub const PROBE_DIR: &str = "/run/meister-install/probe";

/// Asking the kernel what is plugged in.
const QUICK: Duration = Duration::from_secs(30);

/// Partitioning, and mounting what came out of it.
const DISKO: Duration = Duration::from_secs(900);

/// Copying a closure onto a fresh filesystem. An hour, because the store
/// this copies FROM is on the medium and a slow usb stick is a real thing.
const INSTALL: Duration = Duration::from_secs(3600);

/// How far a disk's real size may be from the one the inventory declared.
///
/// Two percent. Disks are sold in decimal gigabytes and the inventory
/// records `size_gb * 10^9`, but a vendor's "960 GB" is 960 197 124 096
/// bytes on one model and 960 000 000 000 on the next, and a partition table
/// or a host protected area takes a little more off. What this check is for
/// is the case where somebody typed the serial of the 480 GB disk while
/// meaning the 960 — and that is a factor of two, not two percent.
pub const SIZE_TOLERANCE: f64 = 0.02;

// ---------------------------------------------------------------------------
// The two files
// ---------------------------------------------------------------------------

/// The disk the inventory declared, as the medium carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetDisk {
    pub serial: String,
    pub wwn: Option<String>,
    pub size_bytes: u64,
}

/// One path this host keeps on a device of its own, and which device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Persistence {
    pub path: String,
    /// `label:meister-data`, `uuid:…`, `partlabel:…` or `serial:…` — never a
    /// device path.
    pub device_ref: String,
    pub required: bool,
}

/// `/etc/meister-install/target.json`: which machine this medium installs.
///
/// There is deliberately no `release_id` in it. An ISO derivation is fixed
/// before any release exists — it is named by the manifest, and the release
/// is made later out of the same evaluation — so a release id here would be
/// either absent or a lie. The honest back-reference is the toplevel path,
/// which a release names too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstallTarget {
    pub schema: String,
    pub fleet: String,
    pub host: String,
    pub boot_mode: BootMode,
    pub toplevel: String,
    /// The script the host's own layout built: destroy, create, mount.
    pub disko_script: String,
    /// What the inventory called the layout, for the summary.
    pub layout: String,
    pub disk: TargetDisk,
    /// Every block device the layout names, as the host module bound it.
    pub layout_devices: Vec<String>,
    pub preserve: Vec<String>,
    pub persistence: Vec<Persistence>,
}

impl InstallTarget {
    pub fn from_json(text: &str, origin: &str) -> Result<InstallTarget> {
        let target: InstallTarget =
            crate::manifest::parse_checked(text, origin, INSTALL_TARGET_SCHEMA)?;
        if target.schema != INSTALL_TARGET_SCHEMA {
            bail!(
                "{origin} says its schema is {:?}, and this installer reads \
                 {INSTALL_TARGET_SCHEMA:?}. The medium and the binary on it come out of one \
                 derivation, so two different answers here mean somebody assembled a medium \
                 by hand.",
                target.schema
            );
        }
        Ok(target)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the install target as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// `/etc/meister-install/installed.json` on the installed system: what was
/// put on this disk, when, and which identity came out of it.
///
/// It is the reason a second boot of the same medium does not format the
/// machine again, and it is the reason an operator can tell an installed
/// disk from a blank one without booting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstalledMark {
    pub schema: String,
    pub host: String,
    pub toplevel: String,
    /// The disk's serial, as the medium was told it.
    pub disk: String,
    pub installed_at: DateTime<Utc>,
    /// `SHA256:…` of the host key this installation generated — the string
    /// `meister-deploy keys enroll` is given.
    pub host_key_fingerprint: String,
    pub machine_id: String,
    /// The plan this installation belongs to, when there was one.
    pub plan_id: Option<String>,
}

impl InstalledMark {
    pub fn from_json(text: &str, origin: &str) -> Result<InstalledMark> {
        crate::manifest::parse_checked(text, origin, INSTALLED_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the installation mark as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// What the kernel says is plugged in
// ---------------------------------------------------------------------------

/// One entry of `lsblk -J`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub wwn: Option<String>,
    /// `-b`, so bytes — but older util-linux answers with a string and
    /// newer with a number, and a tool that only read one of them would
    /// break on whichever installer medium it was not tested on.
    #[serde(default)]
    pub size: Option<serde_json::Value>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub children: Vec<BlockDevice>,
}

impl BlockDevice {
    pub fn size_bytes(&self) -> Option<u64> {
        match &self.size {
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn is_disk(&self) -> bool {
        self.kind.as_deref() == Some("disk")
    }
}

#[derive(Debug, Deserialize)]
struct Lsblk {
    blockdevices: Vec<BlockDevice>,
}

/// `lsblk -J -b -o NAME,PATH,SERIAL,WWN,SIZE,TYPE,MODEL`.
///
/// `MODEL` is one column more than the brief asked for, and it is in the
/// summary a person confirms: "1 disk, 960 GB" is a sentence about any disk,
/// and "SAMSUNG MZQL2960 / MEISTERBOX0001, 960 GB" is a sentence about one.
pub fn lsblk_cmd() -> Cmd {
    Cmd::new(Effect::Read, "lsblk", QUICK).args([
        "-J",
        "-b",
        "-o",
        "NAME,PATH,SERIAL,WWN,SIZE,TYPE,MODEL",
    ])
}

pub fn parse_lsblk(text: &str, origin: &str) -> Result<Vec<BlockDevice>> {
    let parsed: Lsblk = serde_json::from_str(text)
        .map_err(|e| anyhow::anyhow!("{origin} did not answer with json this tool reads: {e}."))?;
    Ok(parsed.blockdevices)
}

// ---------------------------------------------------------------------------
// The verb
// ---------------------------------------------------------------------------

/// What `confirm` found and what it did, in the shape `--json` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub schema: String,
    pub host: String,
    pub fleet: String,
    pub boot_mode: String,
    pub toplevel: String,
    pub disk: String,
    pub device: String,
    pub model: Option<String>,
    pub size_bytes: u64,
    pub declared_size_bytes: u64,
    pub preserve: Vec<String>,
    pub reinstall: bool,
    pub plan_id: Option<String>,
    /// Null for a dry run, which is the whole difference between the two.
    pub installed: Option<InstalledMark>,
    /// What a person is to do next, in one sentence.
    pub next: String,
}

pub const OUTCOME_SCHEMA: &str = "meister-deploy/install-result/1";

/// The disk that was chosen, with what the summary needs to describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub device: BlockDevice,
    /// Its partitions, as lsblk listed them.
    pub partitions: Vec<BlockDevice>,
}

pub struct Installer<'a> {
    pub runner: &'a dyn Runner,
    pub files: &'a dyn Files,
    pub clock: &'a dyn Clock,
    /// `/etc/meister-install/target.json` on a medium; a file in a temporary
    /// directory in a test.
    pub target_path: PathBuf,
    /// Where the target's filesystems end up. disko's `rootMountPoint`.
    pub root: PathBuf,
    /// Where a partition is mounted for a moment while the mark is looked
    /// for.
    pub probe_dir: PathBuf,
}

impl<'a> Installer<'a> {
    pub fn new(
        runner: &'a dyn Runner,
        files: &'a dyn Files,
        clock: &'a dyn Clock,
    ) -> Installer<'a> {
        Installer {
            runner,
            files,
            clock,
            target_path: PathBuf::from(TARGET_PATH),
            root: PathBuf::from(ROOT),
            probe_dir: PathBuf::from(PROBE_DIR),
        }
    }

    pub fn with_target(mut self, path: impl Into<PathBuf>) -> Installer<'a> {
        self.target_path = path.into();
        self
    }

    pub fn with_root(mut self, path: impl Into<PathBuf>) -> Installer<'a> {
        self.root = path.into();
        self
    }

    pub fn with_probe_dir(mut self, path: impl Into<PathBuf>) -> Installer<'a> {
        self.probe_dir = path.into();
        self
    }

    /// (a) What this medium is for.
    pub fn target(&self, host: &str) -> Result<InstallTarget> {
        let origin = self.target_path.display().to_string();
        let text = self.files.read_to_string(&self.target_path).map_err(|e| {
            anyhow::anyhow!(
                "{origin} could not be read ({e}). This program runs on an installer medium \
                 built by `meister-deploy image --kind installer`, and that file is what says \
                 which machine the medium is for."
            )
        })?;
        let target = InstallTarget::from_json(&text, &origin)?;
        if target.host != host {
            bail!(
                "this medium installs the host {} of the fleet {}, and you asked for {host}. \
                 One medium is one host: it carries that host's system and that host's \
                 partition table, and installing it as somebody else would give you a machine \
                 with the wrong name, the wrong addresses and the wrong roles.",
                target.host,
                target.fleet
            );
        }
        Ok(target)
    }

    /// (b) Exactly one disk with that serial, and it is the size it should
    /// be.
    pub fn disk(&self, target: &InstallTarget, serial: &str, wwn: Option<&str>) -> Result<Chosen> {
        // (b0) The serial that was typed IS the consent, so it has to be a
        // serial, and it has to be the one this medium was made for. Found
        // by the review (F19): the typed value was only ever used to pick a
        // device and never compared with `target.disk.serial` — an empty
        // string matched nothing and said so, but the serial of another
        // disk in the same machine would have chosen that disk.
        if serial.trim().is_empty() {
            bail!(
                "--disk needs the serial of the disk to install onto; an empty serial is not \
                 consent. Nothing was changed."
            );
        }
        if serial != target.disk.serial {
            bail!(
                "the serial you typed ({serial}) is not the one this medium was made for ({}): \
                 host {} installs onto that disk and no other. Read the sticker again, or build \
                 the medium for the machine you mean. Nothing was changed.",
                target.disk.serial,
                target.host
            );
        }
        let cmd = lsblk_cmd();
        let out = self.runner.run(&cmd)?;
        let devices = parse_lsblk(&out.stdout, &cmd.line())?;

        let mut matching: Vec<&BlockDevice> = devices
            .iter()
            .filter(|d| d.is_disk() && d.serial.as_deref() == Some(serial))
            .collect();
        if let Some(wwn) = wwn {
            matching.retain(|d| d.wwn.as_deref() == Some(wwn));
        }

        let chosen = match matching.len() {
            1 => matching[0],
            0 => {
                let seen: Vec<String> = devices
                    .iter()
                    .filter(|d| d.is_disk())
                    .map(|d| {
                        format!(
                            "{} ({})",
                            d.path,
                            d.serial.as_deref().unwrap_or("no serial")
                        )
                    })
                    .collect();
                bail!(
                    "no disk with the serial {serial} is present{}. This machine has {}. \
                     Nothing was changed.",
                    match wwn {
                        Some(wwn) => format!(" and the wwn {wwn}"),
                        None => String::new(),
                    },
                    if seen.is_empty() {
                        "no disks at all".to_string()
                    } else {
                        seen.join(", ")
                    }
                );
            }
            _ => {
                let both: Vec<String> = matching
                    .iter()
                    .map(|d| format!("{} (wwn {})", d.path, d.wwn.as_deref().unwrap_or("none")))
                    .collect();
                bail!(
                    "{} disks carry the serial {serial}: {}. That is ambiguous, and this \
                     program will not pick one of them for you — name the wwn as well \
                     (`--wwn <w>`). Nothing was changed.",
                    matching.len(),
                    both.join(", ")
                );
            }
        };

        let Some(size) = chosen.size_bytes() else {
            bail!(
                "lsblk did not say how big {} is, so its size cannot be compared with the {} \
                 bytes the inventory declared. Nothing was changed.",
                chosen.path,
                target.disk.size_bytes
            );
        };
        let declared = target.disk.size_bytes as f64;
        let off = (size as f64 - declared).abs() / declared.max(1.0);
        if off > SIZE_TOLERANCE {
            bail!(
                "the disk {} ({serial}) holds {size} bytes and the inventory declares {} for \
                 this host — {:.1} % apart, and this program allows {:.0} %. Either the \
                 inventory is about a different disk or this is a different disk. Nothing was \
                 changed.",
                chosen.path,
                target.disk.size_bytes,
                off * 100.0,
                SIZE_TOLERANCE * 100.0
            );
        }

        Ok(Chosen {
            device: chosen.clone(),
            partitions: chosen.children.clone(),
        })
    }

    /// (c) The disk the serial found is the disk the layout names.
    ///
    /// This is the bridge the whole verb stands on. An operator types a
    /// SERIAL, because that is what is printed on the disk and what the
    /// inventory records; the layout binds a `/dev/disk/by-id/...` name,
    /// because that is what disko writes a partition table to. The by-id
    /// name carries the transport and the model as well as the serial
    /// (`nvme-<model>_<serial>` against `virtio-<serial>`, measured in M0
    /// probe S7), so neither can be derived from the other — they have to be
    /// compared, through the one thing both resolve to.
    pub fn layout_device(
        &self,
        target: &InstallTarget,
        chosen: &Chosen,
        disk: &str,
    ) -> Result<String> {
        if target.layout_devices.is_empty() {
            bail!(
                "the layout {} names no block device, so there is nothing to check the serial \
                 against. A host module binds one: `disko.devices.disk.main.device = \
                 \"/dev/disk/by-id/…\"`. Nothing was changed.",
                target.layout
            );
        }
        // Astra finding F02, 2026-09-23: this used to return as soon as ONE
        // resolved device equalled the consented disk. `install()` then runs
        // the whole `disko_script`, which disko builds from every disk the
        // layout names — so a layout naming two disks would destroy the
        // second one on consent for the first. Every device the layout names
        // now has to resolve to the one disk that was consented to, or this
        // refuses instead of reaching disks nobody typed a serial for.
        let mut matched = None;
        let mut other: Vec<String> = Vec::new();
        for device in &target.layout_devices {
            let real = self.real_path(device)?;
            if real == disk {
                matched = Some(device.clone());
            } else {
                other.push(format!("{device} -> {real}"));
            }
        }
        match matched {
            Some(device) if other.is_empty() => Ok(device),
            Some(device) => bail!(
                "the layout {} names {} block devices and only {device} is the disk with the \
                 serial {} ({disk}); the others are {}. This installer consents to the one \
                 disk whose serial was typed and refuses a layout that reaches beyond it. \
                 Nothing was changed.",
                target.layout,
                target.layout_devices.len(),
                target.disk.serial,
                other.join(", ")
            ),
            None => bail!(
                "the disk with the serial {} is {} ({}), and the layout {} writes its \
                 partition table to {}. Those are different disks. Either the host module \
                 binds the wrong device or the serial in the inventory belongs to another \
                 machine. Nothing was changed.",
                target.disk.serial,
                chosen.device.path,
                disk,
                target.layout,
                other.join(", ")
            ),
        }
    }

    fn real_path(&self, path: &str) -> Result<String> {
        let cmd = Cmd::new(Effect::Read, "realpath", QUICK).arg(path);
        let out = self.runner.run(&cmd).map_err(|e| {
            anyhow::anyhow!("{path} is not a path this machine has ({e}). Nothing was changed.")
        })?;
        Ok(out.trimmed().to_string())
    }

    /// (d) Whether this disk has been installed before.
    ///
    /// Every partition of it is mounted read-only for a moment and looked
    /// at. Read-only and nosuid/nodev because a disk somebody hands you is
    /// not a disk you trust, and a mount that fails — a swap partition, an
    /// ESP with no filesystem yet, an encrypted volume — is simply a
    /// partition that carries no mark.
    pub fn mark(&self, chosen: &Chosen) -> Result<Option<(String, InstalledMark)>> {
        for partition in &chosen.partitions {
            // Made only when there is something to mount into it, and only
            // when it is not there already: the medium ships the directory
            // (a tmpfiles rule in nix/install.nix), and a `--dry-run` must
            // be able to LOOK for the mark — making a directory is a write,
            // and a dry run does not write.
            if !self.files.exists(&self.probe_dir) {
                self.files.create_dir_all(&self.probe_dir)?;
            }
            let mounted = self.runner.run(
                &Cmd::new(Effect::Read, "mount", QUICK)
                    .args(["-o", "ro,nosuid,nodev"])
                    .arg(&partition.path)
                    .arg(self.probe_dir.display().to_string())
                    .expect(Expect::AnyExit),
            )?;
            if !mounted.ok() {
                continue;
            }
            let path = self.probe_dir.join(MARK_PATH);
            let found = self.files.read_to_string(&path).ok();
            self.runner.run(
                &Cmd::new(Effect::Read, "umount", QUICK).arg(self.probe_dir.display().to_string()),
            )?;
            if let Some(text) = found {
                let mark = InstalledMark::from_json(&text, &path.display().to_string())?;
                return Ok(Some((partition.path.clone(), mark)));
            }
        }
        Ok(None)
    }

    /// (e) Nothing this host preserves is on the disk about to be formatted.
    ///
    /// Preserve means NOT TOUCHED. This program copies nothing anywhere, so
    /// a preserved path that lives on the target disk is a refusal and not a
    /// thing to work around: the disk is destroyed whole, and a promise to
    /// keep something on it would be a promise nobody can keep.
    ///
    /// A device reference that resolves to nothing is a note rather than a
    /// refusal: a disk that is not plugged in is a disk this program is not
    /// about to format.
    pub fn preserve(
        &self,
        target: &InstallTarget,
        chosen: &Chosen,
        disk: &str,
    ) -> Result<Vec<String>> {
        // The disk's own real path is resolved ONCE, in `confirm`, and
        // handed down: `realpath` is a command like any other here, and a
        // test that pins the order of the commands that destroy a partition
        // table should not have to pin the same question asked twice.
        let on_the_disk: Vec<String> = std::iter::once(disk.to_string())
            .chain(
                chosen
                    .partitions
                    .iter()
                    .map(|p| self.real_path(&p.path))
                    .collect::<Result<Vec<_>>>()?,
            )
            .collect();

        let by_path: BTreeMap<&str, &Persistence> = target
            .persistence
            .iter()
            .map(|p| (p.path.as_str(), p))
            .collect();

        let mut notes = Vec::new();
        for path in &target.preserve {
            let Some(entry) = by_path.get(path.as_str()) else {
                bail!(
                    "this host preserves {path} across a reinstall and its inventory says \
                     nothing about which device that path lives on. `persistence = [{{ path = \
                     \"{path}\", device = \"label:…\" }}]` is what says it, and without it \
                     nobody can tell whether {path} is on the disk that is about to be \
                     destroyed. Nothing was changed."
                );
            };
            let Some(device) = device_of(&entry.device_ref)? else {
                notes.push(format!(
                    "{path} is on {} and this tool does not resolve that kind of reference; \
                     check by hand that it is not on {}",
                    entry.device_ref, chosen.device.path
                ));
                continue;
            };
            let Ok(real) = self.real_path(&device) else {
                notes.push(format!(
                    "{path} is on {} ({device}), which is not plugged into this machine — so \
                     it is not on the disk about to be formatted either",
                    entry.device_ref
                ));
                continue;
            };
            if on_the_disk.contains(&real) {
                bail!(
                    "cannot preserve {path}: it is on {} ({real}), which is part of the disk \
                     that is about to be formatted. This program copies nothing anywhere — \
                     preserve means the bytes are not touched — so move that filesystem to \
                     another disk, or take {path} out of `install.preserve`. Nothing was \
                     changed.",
                    entry.device_ref
                );
            }
            notes.push(format!(
                "{path} stays on {} ({real}), which is not this disk",
                entry.device_ref
            ));
        }
        Ok(notes)
    }

    /// (f) What is about to happen, in the words somebody has to agree with.
    pub fn summary(
        &self,
        target: &InstallTarget,
        chosen: &Chosen,
        layout_device: &str,
        mark: Option<&(String, InstalledMark)>,
        preserve_notes: &[String],
        reinstall: bool,
    ) -> String {
        let mut out = String::new();
        let size = chosen.device.size_bytes().unwrap_or(0);
        out.push_str(&format!("host       {} of {}\n", target.host, target.fleet));
        out.push_str(&format!("system     {}\n", target.toplevel));
        out.push_str(&format!("boot mode  {}\n", target.boot_mode));
        out.push_str(&format!(
            "disk       {} ({}), serial {}, {} bytes ({} GB){}\n",
            chosen.device.path,
            chosen.device.model.as_deref().unwrap_or("no model"),
            target.disk.serial,
            size,
            size / 1_000_000_000,
            match chosen.device.wwn.as_deref() {
                Some(wwn) => format!(", wwn {wwn}"),
                None => String::new(),
            }
        ));
        out.push_str(&format!(
            "layout     {} -> {layout_device}\n",
            target.layout
        ));
        out.push_str(&format!(
            "partitions {}\n",
            if chosen.partitions.is_empty() {
                "none — this disk is blank".to_string()
            } else {
                chosen
                    .partitions
                    .iter()
                    .map(|p| p.path.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        for note in preserve_notes {
            out.push_str(&format!("preserve   {note}\n"));
        }
        if target.preserve.is_empty() {
            out.push_str("preserve   nothing: this host keeps no path across a reinstall\n");
        }
        match mark {
            Some((partition, mark)) => out.push_str(&format!(
                "installed  {} on {} carries {} installed at {} (host key {})\n",
                partition, mark.host, mark.toplevel, mark.installed_at, mark.host_key_fingerprint
            )),
            None => out.push_str("installed  no: no partition of this disk carries a mark\n"),
        }
        out.push_str(&format!(
            "about to   {} every partition of {}\n",
            if reinstall {
                "REINSTALL over"
            } else {
                "DESTROY"
            },
            chosen.device.path
        ));
        out
    }

    /// The whole of it: five refusals, a summary, and then — only then —
    /// the four commands that change the machine.
    #[allow(clippy::too_many_arguments)]
    pub fn confirm(
        &self,
        host: &str,
        serial: &str,
        wwn: Option<&str>,
        reinstall: bool,
        plan_id: Option<&str>,
        dry_run: bool,
    ) -> Result<(Outcome, String)> {
        let target = self.target(host)?;
        let chosen = self.disk(&target, serial, wwn)?;
        let disk = self.real_path(&chosen.device.path)?;
        let layout_device = self.layout_device(&target, &chosen, &disk)?;
        let mark = self.mark(&chosen)?;
        if let Some((partition, found)) = &mark
            && !reinstall
        {
            bail!(
                "{} is already installed: {partition} carries an installation mark that says \
                 the host {} was put on this disk at {} with the system {} and the host key \
                 {}. Installing again destroys that machine's identity and everything on the \
                 disk. If that is what you mean, say `--reinstall`. Nothing was changed.",
                chosen.device.path,
                found.host,
                found.installed_at,
                found.toplevel,
                found.host_key_fingerprint
            );
        }
        let preserve_notes = self.preserve(&target, &chosen, &disk)?;
        let summary = self.summary(
            &target,
            &chosen,
            &layout_device,
            mark.as_ref(),
            &preserve_notes,
            reinstall,
        );

        let mut outcome = Outcome {
            schema: OUTCOME_SCHEMA.to_string(),
            host: target.host.clone(),
            fleet: target.fleet.clone(),
            boot_mode: target.boot_mode.to_string(),
            toplevel: target.toplevel.clone(),
            disk: target.disk.serial.clone(),
            device: chosen.device.path.clone(),
            model: chosen.device.model.clone(),
            size_bytes: chosen.device.size_bytes().unwrap_or(0),
            declared_size_bytes: target.disk.size_bytes,
            preserve: target.preserve.clone(),
            reinstall,
            plan_id: plan_id.map(str::to_string),
            installed: None,
            next: String::new(),
        };

        if dry_run {
            outcome.next = format!(
                "nothing was changed. A real run would destroy every partition of {}, install \
                 {} and generate this machine's first host key.",
                chosen.device.path, target.toplevel
            );
            return Ok((outcome, summary));
        }

        let installed = self.install(&target, &chosen, plan_id)?;
        outcome.next = match target.boot_mode {
            BootMode::Uefi => format!(
                "power off, remove the medium and boot from {}. Then enrol this machine with \
                 `meister-deploy keys enroll {} --fingerprint {}`.",
                chosen.device.path, target.host, installed.host_key_fingerprint
            ),
            BootMode::Direct => format!(
                "power off and remove the medium. This host has no boot loader: start it with \
                 the kernel, the initrd and the command line of its release \
                 (`meister-deploy image --release <r.json> --host {} --kind direct-boot`). \
                 Then enrol it with `meister-deploy keys enroll {} --fingerprint {}`.",
                target.host, target.host, installed.host_key_fingerprint
            ),
            // --- lane 5C ---
            // Unreachable in practice and written out all the same: a grub
            // host is one this tool deploys TO and never installs, and the
            // plan refuses `--kind install` for it before anything gets
            // here (nix/lib/inventory.nix says the same thing to the other
            // half). A `_ =>` would make the next boot mode somebody adds
            // silently print a uefi sentence.
            BootMode::Grub => format!(
                "power off and remove the medium. This host is declared `boot = \"grub\"`, \
                 which is a machine that brings its own loader — `meister-install` installed \
                 none. Make it bootable by hand, then enrol it with `meister-deploy keys \
                 enroll {} --fingerprint {}`.",
                target.host, installed.host_key_fingerprint
            ),
            // --- end lane 5C ---
        };
        outcome.installed = Some(installed);
        Ok((outcome, summary))
    }

    /// The four commands that change the machine, in this order and after
    /// everything else.
    fn install(
        &self,
        target: &InstallTarget,
        chosen: &Chosen,
        plan_id: Option<&str>,
    ) -> Result<InstalledMark> {
        // disko: destroy, create, mount. The script is the one the host's
        // own layout built and it carries its mode and its mount point
        // baked in — there is no `--mode` to get wrong here, and no
        // partition table typed by hand.
        self.runner.run(
            &Cmd::new(Effect::TargetWrite, &target.disko_script, DISKO)
                .env("PATH", "/run/current-system/sw/bin"),
        )?;

        // `--no-channel-copy`, because the system is already in this
        // medium's store (`isoImage.storeContents`) and a channel is the
        // pre-flake road this fleet does not take.
        self.runner.run(
            &Cmd::new(Effect::TargetWrite, "nixos-install", INSTALL).args([
                "--system".to_string(),
                target.toplevel.clone(),
                "--root".to_string(),
                self.root.display().to_string(),
                "--no-root-passwd".to_string(),
                "--no-channel-copy".to_string(),
            ]),
        )?;

        // The machine's first identity, made HERE and never travelling: the
        // private half is written onto the disk that was just installed and
        // the public half is what a person carries to `keys enroll`.
        let key = self.root.join("etc/ssh/ssh_host_ed25519_key");
        self.files.create_dir_all(&self.root.join("etc/ssh"))?;
        self.runner.run(
            &Cmd::new(Effect::Key, "ssh-keygen", QUICK)
                .args(["-t", "ed25519", "-N", ""])
                .arg("-f")
                .arg(key.display().to_string()),
        )?;
        let shown = self.runner.run(
            &Cmd::new(Effect::Read, "ssh-keygen", QUICK)
                .arg("-lf")
                .arg(format!("{}.pub", key.display())),
        )?;
        let fingerprint = fingerprint_of(shown.trimmed()).ok_or_else(|| {
            anyhow::anyhow!(
                "ssh-keygen printed {:?} and no SHA256 fingerprint could be read out of it. \
                 The key is on the disk; the fingerprint is what somebody has to carry to \
                 `keys enroll`, so this run stops rather than printing nothing.",
                shown.trimmed()
            )
        })?;

        // A machine id per installation, not per image: two machines from
        // one image that share one id are one machine as far as systemd,
        // etcd and every log line is concerned (V08/L04).
        self.runner.run(
            &Cmd::new(Effect::TargetWrite, "systemd-machine-id-setup", QUICK)
                .arg(format!("--root={}", self.root.display())),
        )?;
        let machine_id = self
            .files
            .read_to_string(&self.root.join("etc/machine-id"))
            .map(|text| text.trim().to_string())
            .unwrap_or_default();

        let mark = InstalledMark {
            schema: INSTALLED_SCHEMA.to_string(),
            host: target.host.clone(),
            toplevel: target.toplevel.clone(),
            disk: target.disk.serial.clone(),
            installed_at: self.clock.now(),
            host_key_fingerprint: fingerprint,
            machine_id,
            plan_id: plan_id.map(str::to_string),
        };
        let path = self.root.join(MARK_PATH);
        self.files
            .create_dir_all(path.parent().expect("the mark is a file in a directory"))?;
        self.files.write_atomic(&path, &mark.to_json()?, 0o444)?;

        // Everything disko mounted, in one go, so that the disk is
        // consistent before anybody pulls the power.
        self.runner.run(
            &Cmd::new(Effect::TargetWrite, "umount", QUICK)
                .arg("-R")
                .arg(self.root.display().to_string()),
        )?;
        let _ = chosen;
        Ok(mark)
    }
}

// ---------------------------------------------------------------------------
// The workstation half: what `meister-deploy install` leaves behind
// ---------------------------------------------------------------------------

pub const MEDIA_SCHEMA: &str = "meister-deploy/install-media/1";

/// What was built for one host, so that a second `install` says "this is the
/// medium" instead of building a second one.
///
/// It lives beside the medium in the state directory rather than inside the
/// plan, because a plan is a document about a fleet at a moment and this is a
/// FILE on this workstation: which iso, of which release, for which plan, and
/// what its bytes hash to — the last one so that whoever writes it to a stick
/// can check they wrote the right thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MediaRecord {
    pub schema: String,
    pub host: String,
    pub plan_id: String,
    pub release_id: String,
    /// The link in the state directory, which is also its collector root.
    pub iso: String,
    /// The file in the store the link points at.
    pub store_path: String,
    pub sha256: String,
    pub size: u64,
    pub built_at: DateTime<Utc>,
}

impl MediaRecord {
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the media record as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_json(text: &str, origin: &str) -> Result<MediaRecord> {
        crate::manifest::parse_checked(text, origin, MEDIA_SCHEMA)
    }
}

/// Where the media of a deployment live: `<repo>/.meister-deploy/media`.
pub fn media_dir(state: &crate::state::StateDir) -> PathBuf {
    state.root().join("media")
}

/// The sheet somebody carries to the machine.
///
/// Printed rather than written, and written rather than assumed: everything
/// in it is a fact out of the plan and the release, in the order a person
/// needs it — which disk, which command, what comes back, and where that
/// goes. The one thing it must never become is a list of steps somebody can
/// follow without reading, so the disk's serial is in every one of them.
pub fn sheet(record: &MediaRecord, target: &SheetFacts) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\nThe installer medium for {} of the fleet {}:\n\n",
        record.host, target.fleet
    ));
    out.push_str(&format!("    {}\n", record.iso));
    out.push_str(&format!("    sha256 {}\n", record.sha256));
    out.push_str(&format!(
        "    {} bytes ({} MiB), release {}\n\n",
        record.size,
        record.size / (1024 * 1024),
        record.release_id
    ));
    out.push_str("Write it to a stick or attach it as virtual media, and boot the machine\n");
    out.push_str(&format!(
        "with the disk whose serial is {}. Nothing happens by itself: on the\n",
        target.serial
    ));
    out.push_str("console, type\n\n");
    out.push_str(&format!(
        "    meister-install confirm --host {} --disk {}{}\n\n",
        record.host,
        target.serial,
        if target.reinstall { " --reinstall" } else { "" }
    ));
    out.push_str("It shows you the disk, its model and its size, and what it is about to\n");
    out.push_str("destroy, before it destroys anything. Then it prints one line:\n\n");
    out.push_str("    HOST KEY FINGERPRINT  SHA256:…\n\n");
    out.push_str("Write that down and bring it back here:\n\n");
    out.push_str(&format!(
        "    meister-deploy keys enroll {} --fingerprint SHA256:…\n\n",
        record.host
    ));
    out.push_str(&match target.boot_mode {
        BootMode::Uefi => format!("Afterwards {} boots from its own disk.\n", record.host),
        BootMode::Direct => format!(
            "Afterwards {} has NO boot loader: its provider has to load the kernel, the\n\
             initrd and the command line of this release (`meister-deploy image --release \
             … \n--host {} --kind direct-boot`).\n",
            record.host, record.host
        ),
        // --- lane 5C ---
        BootMode::Grub => format!(
            "Afterwards {} has no boot loader from this installer: `boot = \"grub\"` is a\n\
             machine that brings its own, and this flake installs none for it.\n",
            record.host
        ),
        // --- end lane 5C ---
    });
    if !target.preserve.is_empty() {
        out.push_str(&format!(
            "\nThese paths must not be on that disk, and the installer refuses if they \
             are:\n    {}\n",
            target.preserve.join("\n    ")
        ));
    }
    out
}

/// The facts the sheet needs out of the release, gathered once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheetFacts {
    pub fleet: String,
    pub serial: String,
    pub boot_mode: BootMode,
    pub preserve: Vec<String>,
    pub reinstall: bool,
}

/// `label:meister-data` -> `/dev/disk/by-label/meister-data`.
///
/// `serial:` is not turned into a path on purpose: a serial names a DISK and
/// what a persistent path lives on is a filesystem, so the answer would be a
/// guess about which partition. It comes back as `None` and the summary says
/// so, which is a person's job to check rather than a refusal this tool
/// cannot justify.
pub fn device_of(device_ref: &str) -> Result<Option<String>> {
    let Some((kind, value)) = device_ref.split_once(':') else {
        bail!(
            "{device_ref:?} is not a device reference: it is `label:…`, `uuid:…`, \
             `partlabel:…` or `serial:…`, and never a device path."
        );
    };
    Ok(match kind {
        "label" => Some(format!("/dev/disk/by-label/{value}")),
        "uuid" => Some(format!("/dev/disk/by-uuid/{value}")),
        "partlabel" => Some(format!("/dev/disk/by-partlabel/{value}")),
        "serial" => None,
        other => bail!(
            "{device_ref:?} names the device kind {other:?}, and this tool knows label, uuid, \
             partlabel and serial."
        ),
    })
}

/// The `SHA256:…` out of `ssh-keygen -lf`, which prints
/// `256 SHA256:<base64> root@host (ED25519)`.
pub fn fingerprint_of(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|word| word.starts_with("SHA256:"))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::{FakeClock, MemFiles};
    use crate::run::{Matcher, Output, Policy, StrictFake};

    const DISK: &str = "/dev/vdb";
    const BY_ID: &str = "/dev/disk/by-id/virtio-MEISTERTEST01";
    const TOPLEVEL: &str = "/nix/store/tttt-nixos-system-box-25.11";
    const DISKO: &str = "/nix/store/dddd-disko";
    const SIZE: u64 = 8_000_000_000;

    fn target() -> InstallTarget {
        InstallTarget {
            schema: INSTALL_TARGET_SCHEMA.to_string(),
            fleet: "one-box".to_string(),
            host: "box".to_string(),
            boot_mode: BootMode::Uefi,
            toplevel: TOPLEVEL.to_string(),
            disko_script: DISKO.to_string(),
            layout: "disko/single-nvme.nix".to_string(),
            disk: TargetDisk {
                serial: "MEISTERTEST01".to_string(),
                wwn: None,
                size_bytes: SIZE,
            },
            layout_devices: vec![BY_ID.to_string()],
            preserve: Vec::new(),
            persistence: Vec::new(),
        }
    }

    /// An lsblk answer: one blank target disk, one other disk, and the root
    /// disk of the medium.
    fn lsblk(partitions: &[&str], size: u64) -> String {
        let children: Vec<String> = partitions
            .iter()
            .map(|p| {
                format!(
                    r#"{{"name":"{n}","path":"{p}","serial":null,"wwn":null,"size":1000,"type":"part"}}"#,
                    n = p.trim_start_matches("/dev/")
                )
            })
            .collect();
        format!(
            r#"{{"blockdevices":[
              {{"name":"vda","path":"/dev/vda","serial":"MEDIUM","wwn":null,"size":500000000,
                "type":"disk","model":"the medium"}},
              {{"name":"vdb","path":"{DISK}","serial":"MEISTERTEST01","wwn":null,"size":{size},
                "type":"disk","model":"QEMU HARDDISK","children":[{children}]}},
              {{"name":"vdc","path":"/dev/vdc","serial":"OTHERDISK","wwn":null,"size":{size},
                "type":"disk","model":"QEMU HARDDISK"}}
            ]}}"#,
            children = children.join(",")
        )
    }

    fn files_with(target: &InstallTarget) -> MemFiles {
        MemFiles::new().given(
            TARGET_PATH,
            String::from_utf8(target.to_json().unwrap()).unwrap(),
        )
    }

    fn installer<'a>(
        runner: &'a StrictFake,
        files: &'a MemFiles,
        clock: &'a FakeClock,
    ) -> Installer<'a> {
        Installer::new(runner, files, clock)
    }

    fn lsblk_matcher() -> Matcher {
        Matcher::prefix("lsblk", ["-J", "-b", "-o"])
    }

    fn realpath(path: &str) -> Matcher {
        Matcher::exact("realpath", [path])
    }

    // -----------------------------------------------------------------
    // (a) which host
    // -----------------------------------------------------------------

    #[test]
    fn a_medium_is_one_hosts_and_says_so() {
        let runner = StrictFake::new();
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .target("n1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("installs the host box"), "{err}");
        assert!(err.contains("One medium is one host"), "{err}");
        runner
            .verify()
            .expect("nothing was run: it never got that far");
    }

    #[test]
    fn a_medium_that_is_not_one_says_what_it_is_for() {
        let runner = StrictFake::new();
        let files = MemFiles::new();
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .target("box")
            .unwrap_err()
            .to_string();
        assert!(err.contains("image --kind installer"), "{err}");
        runner.verify().unwrap();
    }

    // -----------------------------------------------------------------
    // (b) which disk
    // -----------------------------------------------------------------

    #[test]
    fn exactly_one_disk_with_that_serial() {
        let runner = StrictFake::new().expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE)));
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let chosen = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .expect("one disk carries it");
        assert_eq!(chosen.device.path, DISK);
        assert_eq!(chosen.device.model.as_deref(), Some("QEMU HARDDISK"));
        assert!(chosen.partitions.is_empty(), "the disk is blank");
        runner.verify().unwrap();
    }

    #[test]
    fn no_disk_with_that_serial_lists_the_ones_there_are() {
        // The medium's disk is not in this machine: the one that is there
        // carries another serial.
        let runner = StrictFake::new().expect(
            lsblk_matcher(),
            Output::stdout(lsblk(&[], SIZE).replace("MEISTERTEST01", "OTHERDISK99")),
        );
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no disk with the serial MEISTERTEST01"),
            "{err}"
        );
        assert!(err.contains("OTHERDISK99"), "{err}");
        assert!(err.contains("Nothing was changed"), "{err}");
        runner.verify().unwrap();
    }

    /// Review finding F19: the typed serial is the consent, so it is compared
    /// with the one the medium was made for BEFORE any disk is looked at.
    #[test]
    fn a_serial_that_is_not_the_mediums_is_refused_before_any_disk_is_read() {
        let runner = StrictFake::new();
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .disk(&target(), "SOMETHINGELSE", None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not the one this medium was made for"),
            "{err}"
        );
        assert!(err.contains("MEISTERTEST01"), "{err}");
        assert!(err.contains("Nothing was changed"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn an_empty_serial_is_not_consent() {
        let runner = StrictFake::new();
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .disk(&target(), "  ", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not consent"), "{err}");
        runner.verify().unwrap();
    }

    #[test]
    fn two_disks_with_one_serial_are_ambiguous_and_ask_for_the_wwn() {
        let answer = lsblk(&[], SIZE).replace(
            r#""serial":"OTHERDISK","wwn":null"#,
            r#""serial":"MEISTERTEST01","wwn":"nvme.0000-2222""#,
        );
        let runner = StrictFake::new().expect(lsblk_matcher(), Output::stdout(answer.clone()));
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("2 disks carry the serial"), "{err}");
        assert!(err.contains("--wwn"), "{err}");
        runner.verify().unwrap();

        // …and the wwn settles it.
        let runner = StrictFake::new().expect(lsblk_matcher(), Output::stdout(answer));
        let chosen = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", Some("nvme.0000-2222"))
            .expect("one of the two");
        assert_eq!(chosen.device.path, "/dev/vdc");
        runner.verify().unwrap();
    }

    #[test]
    fn a_disk_of_the_wrong_size_is_a_different_disk() {
        // Half the size: somebody typed the serial of the small one.
        let runner =
            StrictFake::new().expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE / 2)));
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("50.0 % apart"), "{err}");
        assert!(err.contains("allows 2 %"), "{err}");
        runner.verify().unwrap();

        // …and a disk that is a percent off is the same disk: a vendor's
        // "8 GB" and a partition table's overhead are not a mistake.
        let runner = StrictFake::new().expect(
            lsblk_matcher(),
            Output::stdout(lsblk(&[], SIZE - SIZE / 100)),
        );
        installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .expect("one percent is not a different disk");
        runner.verify().unwrap();
    }

    // -----------------------------------------------------------------
    // (c) the layout's device
    // -----------------------------------------------------------------

    #[test]
    fn the_serial_has_to_find_the_disk_the_layout_writes_to() {
        let runner = StrictFake::new()
            .expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE)))
            .expect(realpath(BY_ID), Output::stdout("/dev/vdb\n"));
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let chosen = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .unwrap();
        let device = installer(&runner, &files, &clock)
            .layout_device(&target(), &chosen, "/dev/vdb")
            .expect("the same disk");
        assert_eq!(device, BY_ID);
        runner.verify().unwrap();

        // The other way round: a host module that binds somebody else's
        // disk is exactly the mistake this check exists for.
        let runner = StrictFake::new().expect(realpath(BY_ID), Output::stdout("/dev/vdc\n"));
        let err = installer(&runner, &files, &clock)
            .layout_device(&target(), &chosen, "/dev/vdb")
            .unwrap_err()
            .to_string();
        assert!(err.contains("different disks"), "{err}");
        assert!(err.contains("/dev/vdc"), "{err}");
        runner.verify().unwrap();
    }

    /// Astra finding F02, 2026-09-23: one resolved match used to be the
    /// whole layout's consent, and `install()` runs the WHOLE `disko_script`
    /// — every disk the layout names, not just the one that was checked. A
    /// layout naming a second disk must refuse rather than silently reach
    /// it.
    #[test]
    fn layout_device_refuses_a_layout_that_reaches_a_second_disk() {
        let runner = StrictFake::new().expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE)));
        let files = files_with(&target());
        let clock = FakeClock::fixed();
        let chosen = installer(&runner, &files, &clock)
            .disk(&target(), "MEISTERTEST01", None)
            .unwrap();
        runner.verify().unwrap();

        let mut two_disks = target();
        let second = "/dev/disk/by-id/virtio-OTHERDISK99";
        two_disks.layout_devices = vec![BY_ID.to_string(), second.to_string()];

        let runner = StrictFake::new()
            .expect(realpath(BY_ID), Output::stdout("/dev/vdb\n"))
            .expect(realpath(second), Output::stdout("/dev/vdc\n"));
        let err = installer(&runner, &files, &clock)
            .layout_device(&two_disks, &chosen, "/dev/vdb")
            .unwrap_err()
            .to_string();
        assert!(err.contains("consents to the one disk"), "{err}");
        assert!(err.contains(second), "{err}");
        runner.verify().unwrap();
    }

    // -----------------------------------------------------------------
    // (d) the mark
    // -----------------------------------------------------------------

    fn a_mark() -> InstalledMark {
        InstalledMark {
            schema: INSTALLED_SCHEMA.to_string(),
            host: "box".to_string(),
            toplevel: "/nix/store/oooo-nixos-system-box-25.11".to_string(),
            disk: "MEISTERTEST01".to_string(),
            installed_at: crate::fixtures::at("2026-09-20T09:00:00Z"),
            host_key_fingerprint: "SHA256:theoldone".to_string(),
            machine_id: "0123456789abcdef0123456789abcdef".to_string(),
            plan_id: None,
        }
    }

    #[test]
    fn a_disk_that_is_already_installed_is_not_installed_again() {
        let mark_json = String::from_utf8(a_mark().to_json().unwrap()).unwrap();
        let expectations = |fake: StrictFake| {
            fake.expect(
                lsblk_matcher(),
                Output::stdout(lsblk(&["/dev/vdb1", "/dev/vdb2"], SIZE)),
            )
            .expect(realpath(DISK), Output::stdout("/dev/vdb\n"))
            .expect(realpath(BY_ID), Output::stdout("/dev/vdb\n"))
            // The ESP first, and it has no filesystem this medium can read.
            .expect(
                Matcher::prefix("mount", ["-o", "ro,nosuid,nodev", "/dev/vdb1"]),
                Output::failing(32, "unknown filesystem type"),
            )
            .expect(
                Matcher::prefix("mount", ["-o", "ro,nosuid,nodev", "/dev/vdb2"]),
                Output::stdout(""),
            )
            .expect(Matcher::exact("umount", [PROBE_DIR]), Output::stdout(""))
        };

        let files =
            files_with(&target()).given(format!("{PROBE_DIR}/{MARK_PATH}"), mark_json.clone());
        let clock = FakeClock::fixed();

        // Without --reinstall: refused, and the mark is shown.
        let runner = expectations(StrictFake::new());
        let err = installer(&runner, &files, &clock)
            .confirm("box", "MEISTERTEST01", None, false, None, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is already installed"), "{err}");
        assert!(err.contains("SHA256:theoldone"), "{err}");
        assert!(err.contains("--reinstall"), "{err}");
        assert!(err.contains("Nothing was changed"), "{err}");
        runner.verify().unwrap();
    }

    // -----------------------------------------------------------------
    // (e) what must not be on this disk
    // -----------------------------------------------------------------

    #[test]
    fn a_preserved_path_on_the_target_disk_is_a_refusal() {
        let mut target = target();
        target.preserve = vec!["/var/lib/meister-data".to_string()];
        target.persistence = vec![Persistence {
            path: "/var/lib/meister-data".to_string(),
            device_ref: "label:meister-data".to_string(),
            required: true,
        }];
        let chosen = Chosen {
            device: BlockDevice {
                name: "vdb".to_string(),
                path: DISK.to_string(),
                serial: Some("MEISTERTEST01".to_string()),
                wwn: None,
                size: Some(serde_json::json!(SIZE)),
                kind: Some("disk".to_string()),
                model: None,
                children: Vec::new(),
            },
            partitions: vec![BlockDevice {
                name: "vdb2".to_string(),
                path: "/dev/vdb2".to_string(),
                serial: None,
                wwn: None,
                size: Some(serde_json::json!(1000)),
                kind: Some("part".to_string()),
                model: None,
                children: Vec::new(),
            }],
        };
        let files = files_with(&target);
        let clock = FakeClock::fixed();

        // On the disk that is about to be destroyed.
        let runner = StrictFake::new()
            .expect(realpath("/dev/vdb2"), Output::stdout("/dev/vdb2\n"))
            .expect(
                realpath("/dev/disk/by-label/meister-data"),
                Output::stdout("/dev/vdb2\n"),
            );
        let err = installer(&runner, &files, &clock)
            .preserve(&target, &chosen, "/dev/vdb")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot preserve /var/lib/meister-data"),
            "{err}"
        );
        assert!(err.contains("copies nothing anywhere"), "{err}");
        runner.verify().unwrap();

        // …and on another disk it is a note, not a refusal.
        let runner = StrictFake::new()
            .expect(realpath("/dev/vdb2"), Output::stdout("/dev/vdb2\n"))
            .expect(
                realpath("/dev/disk/by-label/meister-data"),
                Output::stdout("/dev/vdc1\n"),
            );
        let notes = installer(&runner, &files, &clock)
            .preserve(&target, &chosen, "/dev/vdb")
            .expect("another disk is not this disk");
        assert!(
            notes[0].contains("stays on label:meister-data"),
            "{notes:?}"
        );
        runner.verify().unwrap();
    }

    #[test]
    fn a_preserved_path_the_inventory_says_nothing_about_is_a_refusal() {
        let mut target = target();
        target.preserve = vec!["/var/lib/meister-data".to_string()];
        let chosen = Chosen {
            device: BlockDevice {
                name: "vdb".to_string(),
                path: DISK.to_string(),
                serial: None,
                wwn: None,
                size: Some(serde_json::json!(SIZE)),
                kind: Some("disk".to_string()),
                model: None,
                children: Vec::new(),
            },
            partitions: Vec::new(),
        };
        let runner = StrictFake::new();
        let files = files_with(&target);
        let clock = FakeClock::fixed();
        let err = installer(&runner, &files, &clock)
            .preserve(&target, &chosen, "/dev/vdb")
            .unwrap_err()
            .to_string();
        assert!(err.contains("says nothing about which device"), "{err}");
        runner.verify().unwrap();
    }

    // -----------------------------------------------------------------
    // (f) the summary first, then four commands in this order
    // -----------------------------------------------------------------

    /// The whole run of a blank disk, with every command it is allowed to
    /// use and not one more.
    fn blank_disk_run(reinstall: bool) -> StrictFake {
        let mut fake = StrictFake::new()
            .expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE)))
            .expect(realpath(DISK), Output::stdout("/dev/vdb\n"))
            .expect(realpath(BY_ID), Output::stdout("/dev/vdb\n"));
        if reinstall {
            // A reinstall of a blank disk looks exactly like an install of
            // one: there are no partitions to look in.
        }
        fake = fake
            .expect(
                Matcher::exact(DISKO, Vec::<String>::new()),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(
                    "nixos-install",
                    [
                        "--system",
                        TOPLEVEL,
                        "--root",
                        ROOT,
                        "--no-root-passwd",
                        "--no-channel-copy",
                    ],
                ),
                Output::stdout("installing"),
            )
            .expect(
                Matcher::exact(
                    "ssh-keygen",
                    [
                        "-t",
                        "ed25519",
                        "-N",
                        "",
                        "-f",
                        "/mnt/etc/ssh/ssh_host_ed25519_key",
                    ],
                ),
                Output::stdout(""),
            )
            .expect(
                Matcher::exact(
                    "ssh-keygen",
                    ["-lf", "/mnt/etc/ssh/ssh_host_ed25519_key.pub"],
                ),
                Output::stdout("256 SHA256:aBcD1234 root@box (ED25519)\n"),
            )
            .expect(
                Matcher::exact("systemd-machine-id-setup", ["--root=/mnt"]),
                Output::stdout(""),
            )
            .expect(Matcher::exact("umount", ["-R", "/mnt"]), Output::stdout(""));
        fake
    }

    #[test]
    fn a_blank_disk_becomes_a_host_in_this_order_and_no_other() {
        let runner = blank_disk_run(false);
        let files = files_with(&target())
            .given("/mnt/etc/machine-id", "feedfacefeedfacefeedfacefeedface\n");
        let clock = FakeClock::at(crate::fixtures::at("2026-09-22T12:00:00Z"));
        let (outcome, summary) = installer(&runner, &files, &clock)
            .confirm("box", "MEISTERTEST01", None, false, Some("plan-1"), false)
            .expect("a blank disk installs");
        runner.verify().unwrap();

        // The summary names the disk, the model, the size and what is about
        // to happen to it — before any of it happened.
        assert!(summary.contains("QEMU HARDDISK"), "{summary}");
        assert!(summary.contains("this disk is blank"), "{summary}");
        assert!(
            summary.contains("DESTROY every partition of /dev/vdb"),
            "{summary}"
        );
        assert!(
            summary.contains("no partition of this disk carries a mark"),
            "{summary}"
        );

        let mark = outcome.installed.expect("it installed");
        assert_eq!(mark.host_key_fingerprint, "SHA256:aBcD1234");
        assert_eq!(mark.machine_id, "feedfacefeedfacefeedfacefeedface");
        assert_eq!(mark.plan_id.as_deref(), Some("plan-1"));
        assert_eq!(mark.toplevel, TOPLEVEL);

        // …and it is on the disk, where the next medium will look for it.
        let written = files
            .content("/mnt/etc/meister-install/installed.json")
            .expect("the mark was written");
        let back = InstalledMark::from_json(
            std::str::from_utf8(&written).unwrap(),
            "the mark just written",
        )
        .expect("it reads back");
        assert_eq!(back, mark);

        assert!(outcome.next.contains("power off"), "{}", outcome.next);
        assert!(outcome.next.contains("keys enroll box"), "{}", outcome.next);
    }

    #[test]
    fn a_dry_run_gets_all_the_way_to_the_summary_and_no_further() {
        let runner = StrictFake::new()
            .with_policy(Policy::dry_run())
            .expect(lsblk_matcher(), Output::stdout(lsblk(&[], SIZE)))
            .expect(realpath(DISK), Output::stdout("/dev/vdb\n"))
            .expect(realpath(BY_ID), Output::stdout("/dev/vdb\n"));
        let files = files_with(&target()).with_policy(Policy::dry_run());
        let clock = FakeClock::fixed();
        let (outcome, summary) = installer(&runner, &files, &clock)
            .confirm("box", "MEISTERTEST01", None, false, None, true)
            .expect("a dry run looks");
        runner.verify().unwrap();
        assert!(outcome.installed.is_none(), "a dry run installed something");
        assert!(summary.contains("DESTROY every partition"), "{summary}");
        assert!(
            outcome.next.contains("nothing was changed"),
            "{}",
            outcome.next
        );
    }

    #[test]
    fn a_direct_boot_host_is_told_it_has_no_boot_menu() {
        let mut target = target();
        target.boot_mode = BootMode::Direct;
        let runner = blank_disk_run(false);
        let files = files_with(&target).given("/mnt/etc/machine-id", "aa\n");
        let clock = FakeClock::fixed();
        let (outcome, _) = installer(&runner, &files, &clock)
            .confirm("box", "MEISTERTEST01", None, false, None, false)
            .expect("it installs");
        runner.verify().unwrap();
        assert!(outcome.next.contains("no boot loader"), "{}", outcome.next);
        assert!(
            outcome.next.contains("--kind direct-boot"),
            "{}",
            outcome.next
        );
    }

    // -----------------------------------------------------------------
    // the small pieces
    // -----------------------------------------------------------------

    #[test]
    fn a_device_reference_becomes_a_path_or_an_honest_nothing() {
        assert_eq!(
            device_of("label:meister-data").unwrap().as_deref(),
            Some("/dev/disk/by-label/meister-data")
        );
        assert_eq!(
            device_of("uuid:1234-5678").unwrap().as_deref(),
            Some("/dev/disk/by-uuid/1234-5678")
        );
        // A serial names a DISK, and a persistent path lives on a
        // filesystem: turning one into the other would be a guess.
        assert_eq!(device_of("serial:S6PENX0T").unwrap(), None);
        assert!(
            device_of("/dev/sda")
                .unwrap_err()
                .to_string()
                .contains("never a device path")
        );
        assert!(
            device_of("wwid:x")
                .unwrap_err()
                .to_string()
                .contains("label, uuid")
        );
    }

    #[test]
    fn the_fingerprint_is_the_word_that_starts_with_sha256() {
        assert_eq!(
            fingerprint_of("256 SHA256:abc+/= root@box (ED25519)").as_deref(),
            Some("SHA256:abc+/=")
        );
        assert_eq!(fingerprint_of("256 MD5:aa:bb root@box (RSA)"), None);
    }

    #[test]
    fn lsblk_is_read_in_both_shapes_it_answers_in() {
        // Newer util-linux answers `-b` with a number, older with a string.
        let numeric = parse_lsblk(
            r#"{"blockdevices":[{"name":"vda","path":"/dev/vda","size":1024,"type":"disk"}]}"#,
            "lsblk",
        )
        .unwrap();
        assert_eq!(numeric[0].size_bytes(), Some(1024));
        let text = parse_lsblk(
            r#"{"blockdevices":[{"name":"vda","path":"/dev/vda","size":"1024","type":"disk"}]}"#,
            "lsblk",
        )
        .unwrap();
        assert_eq!(text[0].size_bytes(), Some(1024));
    }
}
