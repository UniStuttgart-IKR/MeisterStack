// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Build a NoCloud seed as a FAT12 image labelled `CIDATA`. It contains
//! `user-data`, `meta-data`, and optional `network-config`. VFAT entries preserve
//! the required long names. The writer avoids a runtime filesystem-tool dependency.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::debug;

// The create specification shares the CloudInit type with controllers.
pub use agent_api::spec::CloudInit;

/// Volume label used for the NoCloud seed.
pub const LABEL: &str = "CIDATA";

/// Default metadata with a stable VM instance ID and optional hostname.
pub fn meta_data_for(vm_id: &uuid::Uuid, hostname: Option<&str>) -> String {
    let hostname = hostname.unwrap_or(&vm_id.to_string()).to_string();
    format!("instance-id: {vm_id}\nlocal-hostname: {hostname}\n")
}

/// Build the seed image for one VM and write it to `path`.
pub fn write_seed(path: &Path, vm_id: &uuid::Uuid, config: &CloudInit) -> Result<()> {
    let meta_data = config
        .meta_data
        .clone()
        .unwrap_or_else(|| meta_data_for(vm_id, config.local_hostname.as_deref()));

    let mut files: Vec<(&str, &[u8])> = vec![
        ("user-data", config.user_data.as_bytes()),
        ("meta-data", meta_data.as_bytes()),
    ];
    if let Some(network) = &config.network_config {
        files.push(("network-config", network.as_bytes()));
    }

    let image = fat12(&files);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Publish a complete seed by rename so a VMM cannot open a partially written image.
    let staged = path.with_extension("partial");
    std::fs::write(&staged, &image).with_context(|| format!("writing {}", staged.display()))?;
    std::fs::rename(&staged, path).with_context(|| format!("placing {}", path.display()))?;
    debug!(
        bytes = image.len(),
        files = files.len(),
        "cloud-init seed written"
    );
    Ok(())
}

// --- the FAT12 volume -------------------------------------------------------

const SECTOR: usize = 512;
/// One sector per cluster: the smallest allocation unit, which is what a
/// volume holding three small text files wants.
const SECTORS_PER_CLUSTER: usize = 1;
const RESERVED_SECTORS: usize = 1;
const FATS: usize = 2;
/// Fixed root directory capacity.
const ROOT_ENTRIES: usize = 512;
const ROOT_SECTORS: usize = ROOT_ENTRIES * 32 / SECTOR;
/// Minimum cluster count. Larger inputs increase this value; the writer does
/// not currently reject inputs exceeding the FAT12 cluster limit.
const MIN_CLUSTERS: usize = 2000;

/// Build a FAT12 volume with the supplied root-directory files.
fn fat12(files: &[(&str, &[u8])]) -> Vec<u8> {
    let needed: usize = files
        .iter()
        .map(|(_, bytes)| bytes.len().div_ceil(SECTOR * SECTORS_PER_CLUSTER))
        .sum();
    let clusters = MIN_CLUSTERS.max(needed + 16);
    // Every cluster number is 12 bits, plus the two reserved entries.
    let fat_sectors = ((clusters + 2) * 3).div_ceil(2).div_ceil(SECTOR);
    let total_sectors = RESERVED_SECTORS + FATS * fat_sectors + ROOT_SECTORS + clusters;

    let mut image = vec![0u8; total_sectors * SECTOR];
    boot_sector(&mut image[..SECTOR], total_sectors, fat_sectors);

    // Build one FAT buffer for both on-disk copies.
    let mut fat = vec![0u8; fat_sectors * SECTOR];
    // The two reserved entries: the media descriptor, and end-of-chain.
    set_fat(&mut fat, 0, 0xFF8);
    set_fat(&mut fat, 1, 0xFFF);

    let root_at = (RESERVED_SECTORS + FATS * fat_sectors) * SECTOR;
    let data_at = root_at + ROOT_SECTORS * SECTOR;
    let mut root: Vec<u8> = Vec::new();
    // Write the label in both the boot sector and a directory entry so BPB
    // readers, the Linux vfat driver and blkid identify the NoCloud volume.
    root.extend_from_slice(&dir_entry(LABEL, 0x08, 0, 0));

    let mut next_cluster = 2usize;
    for (index, (name, bytes)) in files.iter().enumerate() {
        let short = short_name(index);
        let first = next_cluster;
        let count = bytes.len().div_ceil(SECTOR * SECTORS_PER_CLUSTER).max(1);
        for i in 0..count {
            let cluster = first + i;
            let value = if i + 1 == count { 0xFFF } else { cluster + 1 };
            set_fat(&mut fat, cluster, value as u16);
        }
        let at = data_at + (first - 2) * SECTOR * SECTORS_PER_CLUSTER;
        image[at..at + bytes.len()].copy_from_slice(bytes);
        next_cluster += count;

        root.extend_from_slice(&long_name_entries(name, &short));
        root.extend_from_slice(&dir_entry(&short, 0x20, first as u16, bytes.len() as u32));
    }

    for i in 0..FATS {
        let at = (RESERVED_SECTORS + i * fat_sectors) * SECTOR;
        image[at..at + fat.len()].copy_from_slice(&fat);
    }
    image[root_at..root_at + root.len()].copy_from_slice(&root);
    image
}

/// The BIOS parameter block. Every field here is either a constant of the
/// shape this writer produces or computed above; nothing is negotiable.
fn boot_sector(sector: &mut [u8], total_sectors: usize, fat_sectors: usize) {
    // A jump nothing executes — this volume is never booted from — followed
    // by the OEM name every tool expects to find something in.
    sector[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    sector[3..11].copy_from_slice(b"MSWIN4.1");
    sector[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    sector[13] = SECTORS_PER_CLUSTER as u8;
    sector[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    sector[16] = FATS as u8;
    sector[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    // Use the short sector count when it fits; otherwise populate the large count.
    // This does not enforce the separate FAT12 cluster-count limit.
    let small = u16::try_from(total_sectors).unwrap_or(0);
    sector[19..21].copy_from_slice(&small.to_le_bytes());
    sector[21] = 0xF8; // fixed disk
    sector[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    sector[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors per track
    sector[26..28].copy_from_slice(&2u16.to_le_bytes()); // heads
    sector[28..32].copy_from_slice(&0u32.to_le_bytes()); // hidden sectors
    let large = if small == 0 { total_sectors as u32 } else { 0 };
    sector[32..36].copy_from_slice(&large.to_le_bytes());
    sector[36] = 0x80; // drive number
    sector[38] = 0x29; // extended boot signature: the three fields below are real
    sector[39..43].copy_from_slice(&0x4349_4441u32.to_le_bytes()); // volume serial
    sector[43..54].copy_from_slice(&padded(LABEL));
    sector[54..62].copy_from_slice(b"FAT12   ");
    sector[510] = 0x55;
    sector[511] = 0xAA;
}

/// Write a packed 12-bit FAT entry; pairs occupy three bytes.
fn set_fat(fat: &mut [u8], cluster: usize, value: u16) {
    let at = cluster * 3 / 2;
    if cluster % 2 == 0 {
        fat[at] = (value & 0xFF) as u8;
        fat[at + 1] = (fat[at + 1] & 0xF0) | ((value >> 8) & 0x0F) as u8;
    } else {
        fat[at] = (fat[at] & 0x0F) | ((value << 4) & 0xF0) as u8;
        fat[at + 1] = ((value >> 4) & 0xFF) as u8;
    }
}

/// An 8.3 name, space-padded to eleven bytes.
fn padded(name: &str) -> [u8; 11] {
    let mut out = [b' '; 11];
    for (i, b) in name.bytes().take(11).enumerate() {
        out[i] = b.to_ascii_uppercase();
    }
    out
}

/// Generate a distinct 8.3 alias for each long-named seed file.
fn short_name(index: usize) -> String {
    format!("SEED{index:04}")
}

/// One 32-byte directory entry.
fn dir_entry(name: &str, attr: u8, first_cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..11].copy_from_slice(&padded(name));
    e[11] = attr;
    // Use 1980-01-01 for reproducible seed bytes.
    let date = (1u16 << 5) | 1;
    e[16..18].copy_from_slice(&date.to_le_bytes());
    e[18..20].copy_from_slice(&date.to_le_bytes());
    e[24..26].copy_from_slice(&date.to_le_bytes());
    e[26..28].copy_from_slice(&first_cluster.to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// Encode VFAT long-name entries before the short entry, in reverse order.
/// Each carries 13 UTF-16 units and the short-name checksum. Sequence numbers
/// start at one; the highest also sets 0x40.
fn long_name_entries(name: &str, short: &str) -> Vec<u8> {
    let checksum = short_checksum(&padded(short));
    let units: Vec<u16> = name.encode_utf16().collect();
    let chunks: Vec<&[u16]> = units.chunks(13).collect();
    let mut out = Vec::with_capacity(chunks.len() * 32);
    // Last chunk first: the run is stored in reverse, so a reader walking
    // forwards meets the highest sequence number first.
    for (i, chunk) in chunks.iter().enumerate().rev() {
        let mut e = [0u8; 32];
        let sequence = (i + 1) as u8;
        e[0] = if i + 1 == chunks.len() {
            sequence | 0x40
        } else {
            sequence
        };
        e[11] = 0x0F; // the attribute combination that marks a long-name entry
        e[13] = checksum;
        // VFAT distributes each name chunk across these UTF-16 slots.
        let slots: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (slot, at) in slots.into_iter().enumerate() {
            let unit = match chunk.get(slot) {
                Some(u) => *u,
                // Terminate with NUL, then pad unused slots with 0xFFFF.
                None if slot == chunk.len() => 0x0000,
                None => 0xFFFF,
            };
            e[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&e);
    }
    out
}

/// The one-byte checksum of an 8.3 name that every long-name entry of a file
/// carries.
fn short_checksum(name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for byte in name {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte);
    }
    sum
}

/// VM seed path under the run directory; rebuilt from the spec during provisioning.
pub fn seed_path(run_dir: &Path, vm_id: &uuid::Uuid) -> PathBuf {
    run_dir.join(format!("{vm_id}.cidata.img"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_le16(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([b[at], b[at + 1]])
    }

    /// Verify the boot sector and FAT12 geometry for a small seed.
    #[test]
    fn the_boot_sector_describes_the_volume_that_follows_it() {
        let image = fat12(&[("user-data", b"#cloud-config\n")]);
        assert_eq!(read_le16(&image, 11), 512, "bytes per sector");
        assert_eq!(image[13], 1, "sectors per cluster");
        assert_eq!(read_le16(&image, 14), 1, "reserved sectors");
        assert_eq!(image[16], 2, "two fats");
        assert_eq!(read_le16(&image, 17), 512, "root entries");
        assert_eq!(image[21], 0xF8, "media descriptor");
        assert_eq!(&image[54..62], b"FAT12   ");
        assert_eq!((image[510], image[511]), (0x55, 0xAA), "signature");

        // The total the BPB claims is the size of the file, which is what a
        // reader that trusts it will walk.
        let total = read_le16(&image, 19) as usize;
        assert_eq!(total * 512, image.len());

        // Under FAT12's ceiling, so a kernel reading this does not decide it
        // is FAT16 and misparse every cluster number.
        let fat_sectors = read_le16(&image, 22) as usize;
        let clusters = total - 1 - 2 * fat_sectors - 32;
        assert!(clusters < 4085, "{clusters} clusters is not FAT12 any more");
    }

    /// The label is what cloud-init finds the volume BY, so it is asserted in
    /// both places it is written and in the exact case the datasource wants.
    #[test]
    fn the_label_is_cidata_in_both_places_it_is_written() {
        let image = fat12(&[("user-data", b"x")]);
        assert_eq!(&image[43..54], b"CIDATA     ", "in the boot sector");

        // And as the first root directory entry, with the volume attribute.
        let fat_sectors = read_le16(&image, 22) as usize;
        let root = (1 + 2 * fat_sectors) * 512;
        assert_eq!(&image[root..root + 11], b"CIDATA     ");
        assert_eq!(image[root + 11], 0x08, "the volume-label attribute");
    }

    /// Find NoCloud files by their VFAT long names and verify their contents.
    #[test]
    fn the_files_are_findable_by_the_names_cloud_init_uses() {
        let user = b"#cloud-config\nssh_authorized_keys:\n  - ssh-ed25519 AAAA...\n";
        let meta = b"instance-id: abc\nlocal-hostname: web-1\n";
        let image = fat12(&[
            ("user-data", user.as_slice()),
            ("meta-data", meta.as_slice()),
        ]);

        let fat_sectors = read_le16(&image, 22) as usize;
        let root_at = (1 + 2 * fat_sectors) * 512;
        let data_at = root_at + 32 * 512;

        for (name, bytes) in [
            ("user-data", user.as_slice()),
            ("meta-data", meta.as_slice()),
        ] {
            let (cluster, size) = find(&image, root_at, name).expect("the name is in the root dir");
            assert_eq!(size as usize, bytes.len(), "{name} size");
            let at = data_at + (cluster as usize - 2) * 512;
            assert_eq!(&image[at..at + bytes.len()], bytes, "{name} content");
        }
    }

    /// Walk the root directory the way a reader does: collect the long-name
    /// run, check its checksum against the short entry it precedes, and
    /// answer with where the file is.
    fn find(image: &[u8], root_at: usize, want: &str) -> Option<(u16, u32)> {
        let mut name = String::new();
        let mut units: Vec<u16> = Vec::new();
        for i in 0..512 {
            let e = &image[root_at + i * 32..root_at + (i + 1) * 32];
            if e[0] == 0 {
                break;
            }
            if e[11] == 0x0F {
                // A long-name entry. The run is stored last-first, so each
                // one prepends.
                let slots: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                let mut chunk: Vec<u16> = Vec::new();
                for at in slots {
                    let unit = read_le16(e, at);
                    if unit == 0x0000 || unit == 0xFFFF {
                        break;
                    }
                    chunk.push(unit);
                }
                let mut joined = chunk;
                joined.extend_from_slice(&units);
                units = joined;
                continue;
            }
            if e[11] & 0x08 != 0 {
                units.clear();
                continue; // the volume label
            }
            // The short-name checksum associates preceding long-name entries.
            let short: [u8; 11] = e[0..11].try_into().unwrap();
            assert_eq!(
                short_checksum(&short),
                image[root_at + (i - 1) * 32 + 13],
                "the long-name run does not belong to the entry it precedes"
            );
            name = String::from_utf16_lossy(&units);
            units = Vec::new();
            if name == want {
                let cluster = read_le16(e, 26);
                let size = u32::from_le_bytes(e[28..32].try_into().unwrap());
                return Some((cluster, size));
            }
        }
        let _ = name;
        None
    }

    /// A file bigger than one cluster gets a chain, and the chain ends. A
    /// user-data with a long script in it is exactly this case.
    #[test]
    fn a_file_larger_than_a_cluster_is_chained_and_terminated() {
        let big = vec![b'y'; 512 * 3 + 7];
        let image = fat12(&[("user-data", big.as_slice())]);
        let fat_sectors = read_le16(&image, 22) as usize;
        let root_at = (1 + 2 * fat_sectors) * 512;
        let (first, size) = find(&image, root_at, "user-data").unwrap();
        assert_eq!(size as usize, big.len());

        // Four clusters: 3 full and one holding the remaining seven bytes.
        let fat = &image[512..512 + fat_sectors * 512];
        let mut walked = vec![first];
        loop {
            let cluster = *walked.last().unwrap() as usize;
            let at = cluster * 3 / 2;
            let entry = if cluster % 2 == 0 {
                (read_le16(fat, at)) & 0x0FFF
            } else {
                (read_le16(fat, at)) >> 4
            };
            if entry >= 0xFF8 {
                break;
            }
            walked.push(entry);
            assert!(walked.len() < 10, "the chain does not end: {walked:?}");
        }
        assert_eq!(walked.len(), 4, "{walked:?}");

        // And the bytes are contiguous across the chain, which is what the
        // allocator above promises.
        let data_at = root_at + 32 * 512;
        let at = data_at + (first as usize - 2) * 512;
        assert_eq!(&image[at..at + big.len()], big.as_slice());

        // Both copies of the table say the same thing.
        let second = &image[512 + fat_sectors * 512..512 + 2 * fat_sectors * 512];
        assert_eq!(fat, second, "the two fats have drifted apart");
    }

    /// Derived metadata uses the VM ID as the stable cloud-init instance-id.
    #[test]
    fn the_derived_meta_data_names_the_vm_and_its_hostname() {
        let id = uuid::Uuid::parse_str("54458d1d-1185-43a8-9672-aa1bd429f3ff").unwrap();
        let with_name = meta_data_for(&id, Some("web-1"));
        assert!(with_name.contains("instance-id: 54458d1d-1185-43a8-9672-aa1bd429f3ff"));
        assert!(with_name.contains("local-hostname: web-1"));

        // No name pushed down: the uid, which is an ugly hostname and an
        // honest one.
        let without = meta_data_for(&id, None);
        assert!(without.contains("local-hostname: 54458d1d-1185-43a8-9672-aa1bd429f3ff"));
    }

    /// Preserve explicit metadata and distinguish absent from empty network configuration.
    #[test]
    fn what_the_spec_says_is_what_is_written() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let dir = temp.path().to_path_buf();
        let id = uuid::Uuid::new_v4();

        let path = dir.join("plain.img");
        write_seed(
            &path,
            &id,
            &CloudInit {
                user_data: "#cloud-config\n".into(),
                meta_data: Some("instance-id: mine\n".into()),
                network_config: None,
                local_hostname: Some("ignored".into()),
            },
        )
        .unwrap();
        let image = std::fs::read(&path).unwrap();
        let fat_sectors = read_le16(&image, 22) as usize;
        let root_at = (1 + 2 * fat_sectors) * 512;
        let data_at = root_at + 32 * 512;
        let (cluster, size) = find(&image, root_at, "meta-data").unwrap();
        let at = data_at + (cluster as usize - 2) * 512;
        assert_eq!(
            &image[at..at + size as usize],
            b"instance-id: mine\n",
            "a given meta-data is used verbatim, hostname and all"
        );
        assert!(find(&image, root_at, "network-config").is_none());

        let path = dir.join("networked.img");
        write_seed(
            &path,
            &id,
            &CloudInit {
                user_data: "#cloud-config\n".into(),
                meta_data: None,
                network_config: Some("version: 2\n".into()),
                local_hostname: None,
            },
        )
        .unwrap();
        let image = std::fs::read(&path).unwrap();
        assert!(find(&image, root_at, "network-config").is_some());
        // And nothing half-written is left behind.
        assert!(!dir.join("networked.partial").exists());
    }
}
