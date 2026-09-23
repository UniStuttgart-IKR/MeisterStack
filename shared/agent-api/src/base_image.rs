// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a base image has to be before a node writes it onto a disk.
//!
//! Astra finding S01, 2026-09-23: both block backends ran `qemu-img convert
//! -O raw <src> <dst>` with no `-f`, so the SOURCE format was whatever
//! qemu-img decided the file was at the moment it opened it — and they
//! refused nothing. Two things follow from that, and neither is theoretical:
//!
//! * A qcow2 with a `backing file` is a file that NAMES another file, and
//!   `qemu-img convert` reads it. So is a qcow2 with an external `data file`.
//!   The name is inside the image and is not a path this stack chose, so an
//!   image somebody uploaded could say `/etc/shadow` — or another tenant's
//!   volume — and the converter would faithfully copy it into a disk that
//!   tenant then boots and reads. The converter runs as the agent, which on
//!   a node with `unprivileged = false` (the default in `nix/agent.nix`) is
//!   root.
//! * Without `-f`, format detection happens twice: once when the size is
//!   measured and once when the bytes are converted. A file that changed
//!   between the two is converted as something other than what was judged.
//!
//! So: one probe, which refuses a backing file, an external data file, a
//! format that is not on the short list, and anything that is not a regular
//! file — and then a convert that is TOLD the format the probe saw.
//!
//! Here rather than in either driver because both do the same thing and both
//! got it wrong the same way. `filesystem` and `lvm-thin` already depend on
//! this crate, and a check that exists twice is a check that will diverge.

use std::ffi::OsString;
use std::path::Path;

use crate::storage::{self, StorageError};

/// The formats a base image may be in.
///
/// Short on purpose. `raw` is a disk and nothing else; `qcow2` is what every
/// cloud image in this lab ships as. Everything else — vmdk, vdi, vhdx, and
/// the qcow2 variants that reference other files — is a format whose
/// behaviour on `convert` somebody would have to read the source of QEMU to
/// state, and a base image is not the place to find out.
pub const CONVERTIBLE_FORMATS: [&str; 2] = ["raw", "qcow2"];

/// A base image this node is willing to convert, and the two facts about it
/// that the caller needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseImage {
    /// What qemu-img says the file IS, handed straight back to it as `-f` so
    /// that the conversion cannot decide something else.
    pub format: String,
    /// What the file occupies once written out raw. For a qcow2 this is the
    /// disk it describes and not the length of the file, which is the number
    /// a size check has to use.
    pub virtual_size: u64,
}

/// Run `qemu-img info --output=json` over the file and judge what it says.
///
/// One subprocess, where there used to be one per backend for the size alone.
/// `name` is the catalogue name and is only ever used to write the sentence a
/// person reads.
pub async fn probe(qemu_img: &Path, path: &Path, name: &str) -> storage::Result<BaseImage> {
    // A directory, a fifo or a device node under a catalogue name is not an
    // image. Asked before qemu-img is started, because "qemu-img could not
    // open it" is a worse sentence than this one and because a fifo would
    // hang the probe rather than fail it.
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| StorageError::ImageNotFound(format!("{name}: {} ({e})", path.display())))?;
    if !meta.is_file() {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} is not a regular file ({})",
            path.display()
        )));
    }

    let out = tokio::process::Command::new(qemu_img)
        .args(["info", "--output=json"])
        .arg(path)
        .output()
        .await
        .map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "running {}: {e} (a base image is measured with it; is qemu-img on the agent's \
                 PATH?)",
                qemu_img.display()
            ))
        })?;
    if !out.status.success() {
        return Err(StorageError::ImageNotFound(format!(
            "{name}: qemu-img info failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    judge(name, &out.stdout)
}

/// Read one `qemu-img info --output=json` document and say whether the file
/// it describes may be converted.
///
/// Split from [`probe`] so that the judgement can be tested against the
/// documents qemu-img really writes, without a qemu-img.
pub fn judge(name: &str, info: &[u8]) -> storage::Result<BaseImage> {
    let info: serde_json::Value = serde_json::from_slice(info).map_err(|e| {
        StorageError::Backend(anyhow::anyhow!("qemu-img info json for {name}: {e}"))
    })?;

    // A backing file is the whole finding in one field: it names a SECOND
    // file, that name is inside the image and was chosen by whoever made it,
    // and `qemu-img convert` reads it as part of the conversion. Both
    // spellings, because qemu-img writes the resolved one beside the one the
    // image holds and an image may carry either.
    for field in ["backing-filename", "full-backing-filename"] {
        if let Some(named) = info.get(field).and_then(serde_json::Value::as_str) {
            return Err(StorageError::InvalidSpec(format!(
                "the base image {name} has a backing file ({named:?}); this node converts an \
                 image that is whole in itself and nothing that reads a second file of its own \
                 choosing"
            )));
        }
    }
    // The same thing said the other way round: a qcow2 whose data lives in an
    // external file is metadata pointing at bytes somewhere else.
    if let Some(named) = info
        .pointer("/format-specific/data/data-file")
        .and_then(serde_json::Value::as_str)
    {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} keeps its data in an external file ({named:?}); this node \
             converts an image that is whole in itself"
        )));
    }

    let format = info
        .get("format")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "qemu-img info for {name} does not say what format it is"
            ))
        })?;
    if !CONVERTIBLE_FORMATS.contains(&format) {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} is a {format:?}; this node converts [{}] and nothing else",
            CONVERTIBLE_FORMATS.join(", ")
        )));
    }

    // Parsed and not scanned. The document is not flat: `children[0].info`
    // carries a `virtual-size` of its own for the FILE node — a few hundred
    // kilobytes for a fresh qcow2 — before the top-level one that describes
    // the disk. Taking the first match is how a 64M image passes a check
    // meant to reject it.
    let virtual_size = info
        .get("virtual-size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "qemu-img info for {name} has no virtual-size"
            ))
        })?;

    Ok(BaseImage {
        format: format.to_string(),
        virtual_size,
    })
}

/// The argv of the one conversion this stack performs.
///
/// `-f` is the point of it: without it qemu-img decides for itself what the
/// source is, every time it opens it, and the decision it makes at convert
/// time is not the one the probe judged.
pub fn convert_argv(image: &BaseImage, src: &Path, dst: &Path) -> Vec<OsString> {
    vec![
        OsString::from("convert"),
        OsString::from("-f"),
        OsString::from(&image.format),
        OsString::from("-O"),
        OsString::from("raw"),
        src.as_os_str().to_os_string(),
        dst.as_os_str().to_os_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `qemu-img info --output=json` writes for a plain qcow2, with
    /// whatever this test wants to add to it.
    fn info(extra: serde_json::Value) -> Vec<u8> {
        let mut doc = serde_json::json!({
            "virtual-size": 16777216,
            "filename": "/var/lib/meister/images/noble.qcow2",
            "cluster-size": 65536,
            "format": "qcow2",
            "actual-size": 200704,
            "format-specific": { "type": "qcow2", "data": { "compat": "1.1" } },
            "dirty-flag": false
        });
        let (Some(doc), Some(extra)) = (doc.as_object_mut(), extra.as_object()) else {
            panic!("both are objects");
        };
        for (k, v) in extra {
            doc.insert(k.clone(), v.clone());
        }
        serde_json::to_vec(&serde_json::Value::Object(doc.clone())).expect("json")
    }

    /// An image that is whole in itself is converted, and the size that comes
    /// back is the disk it describes rather than the length of the file.
    #[test]
    fn an_image_that_is_whole_in_itself_is_accepted() {
        let judged = judge("noble.qcow2", &info(serde_json::json!({}))).expect("accepted");
        assert_eq!(judged.format, "qcow2");
        assert_eq!(judged.virtual_size, 16777216);

        let raw = judge(
            "noble.raw",
            &info(serde_json::json!({ "format": "raw", "format-specific": null })),
        )
        .expect("raw is an image too");
        assert_eq!(raw.format, "raw");
    }

    /// Astra finding S01, 2026-09-23: a backing file names a SECOND file, the
    /// name is inside the image, and `qemu-img convert` reads it. An image
    /// somebody uploaded could name a path on the node, and the converter
    /// runs as the agent.
    #[test]
    fn an_image_that_reads_another_file_is_refused() {
        for field in ["backing-filename", "full-backing-filename"] {
            let err = judge(
                "noble.qcow2",
                &info(serde_json::json!({ field: "/etc/shadow" })),
            )
            .expect_err("must not be converted");
            let said = err.to_string();
            assert!(said.contains("backing file"), "{said}");
            assert!(said.contains("/etc/shadow"), "and names it: {said}");
        }
    }

    /// The same thing said the other way round: the metadata is here and the
    /// data is somewhere else.
    #[test]
    fn an_image_whose_data_is_elsewhere_is_refused() {
        let err = judge(
            "noble.qcow2",
            &info(serde_json::json!({
                "format-specific": {
                    "type": "qcow2",
                    "data": { "compat": "1.1", "data-file": "/srv/other-tenant/disk.raw" }
                }
            })),
        )
        .expect_err("must not be converted");
        let said = err.to_string();
        assert!(said.contains("external file"), "{said}");
        assert!(said.contains("other-tenant"), "and names it: {said}");
    }

    /// A format nobody here has reasoned about is refused by name, so the
    /// operator learns which one it was.
    #[test]
    fn a_format_that_is_not_on_the_list_is_refused() {
        let err = judge(
            "somebody.vmdk",
            &info(serde_json::json!({ "format": "vmdk" })),
        )
        .expect_err("not a format this node converts");
        let said = err.to_string();
        assert!(said.contains("vmdk"), "{said}");
        assert!(said.contains("raw, qcow2"), "and says what it does: {said}");

        // And a document that says nothing about the format at all is not
        // read as one that says "raw".
        let mut headless = serde_json::json!({ "virtual-size": 1, "actual-size": 1 });
        headless.as_object_mut().expect("an object");
        assert!(judge("x.raw", serde_json::to_vec(&headless).unwrap().as_slice()).is_err());
    }

    /// The conversion is TOLD what it is reading.
    ///
    /// Astra finding S01, 2026-09-23: without `-f` the format is detected
    /// again at convert time, which is a second decision about a file that
    /// may have changed since the first one — and the first one is the only
    /// one anything checked.
    #[test]
    fn the_conversion_is_told_the_format_that_was_judged() {
        let image = BaseImage {
            format: "qcow2".into(),
            virtual_size: 1 << 24,
        };
        let argv = convert_argv(
            &image,
            Path::new("/images/noble.qcow2"),
            Path::new("/dev/vg/lv"),
        );
        let said: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            said,
            vec![
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "/images/noble.qcow2",
                "/dev/vg/lv"
            ]
        );
    }
}
