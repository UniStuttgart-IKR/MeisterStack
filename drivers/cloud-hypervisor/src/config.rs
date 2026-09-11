// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Bauen der VM-Konfiguration, und sonst nichts.
//!
//! Pure: an `InstanceSpec` and two paths in, one JSON document out, no socket
//! and no process anywhere near it. That is what lets the tests below assert
//! the document itself — the shape cloud hypervisor is handed is the thing
//! this driver is judged on, and it is checkable without a VMM.
//!
//! Moved out of `lib.rs` unchanged.

use super::*;

/// One entry of CH's `disks` array. A path is opened by the VMM itself; a
/// vhost-user-blk socket is a backend process the VMM connects to instead
/// (CH's own `vhost_user`/`vhost_socket` disk fields — the same pair the
/// upstream vhost_user_block daemon is driven with).
///
/// None for an attachment that is not a disk at all: a share is a `fs` entry,
/// and `split_volumes` is what sorts the two apart.
///
/// `image_type` is stated and not left to CH, for two reasons that both bite.
/// Unset is `ImageType::Unknown`, and v53 answers that by auto-detecting, by
/// logging a DEPRECATION warning saying the auto-detection will be removed —
/// and, on detecting raw, by turning OFF sector 0 writes. A guest that writes
/// its own partition table or a bootloader then takes an
/// `I/O error, dev vda, sector 0 op WRITE` for something it is entitled to do.
///
/// `Raw` is right for every path this driver is ever handed, by construction:
/// `lvm-thin` writes the base image onto the LV with `qemu-img convert -O raw`
/// and `filesystem` creates `<id>.raw`. A block driver that ever hands over a
/// qcow2 has to say so here, and this comment is where it will look.
///
/// The spelling is the VARIANT name and not the `Display` one: CH's
/// `ImageType` derives `Deserialize` with no rename, so it reads `"Raw"` and
/// not `"raw"` — the lowercase form is what `Display` prints into its logs,
/// and sending it would fail the whole `vm.create` body.
pub(crate) fn disk_config(disk: &AttachedVolume) -> Option<serde_json::Value> {
    let mut config = match &disk.attachment {
        VolumeAttachment::Path(path) => serde_json::json!({
            "path": path,
            "image_type": "Raw",
        }),
        VolumeAttachment::VhostUserBlk { socket, .. } => serde_json::json!({
            "vhost_user": true,
            "vhost_socket": socket,
        }),
        VolumeAttachment::FsShare { .. } => return None,
    };
    // The name this disk answers to for the rest of its life. CH's own
    // `DiskConfig.id` is optional and it invents `_disk0`, `_disk1`, … when
    // nobody states one — positional names, which move under a hot-unplug and
    // then address the wrong disk. `vm.remove-device` and `vm.resize-disk`
    // both take a disk BY NAME, so the name has to be ours and derived from
    // something that does not move: the volume id. See `hypervisor::disk_id`.
    config["id"] = agent_api::disk_id(&disk.id).into();
    Some(config)
}

/// The VM's disks, in order, with the cloud-init seed last.
///
/// Order is load-bearing: the guest's boot disk is the first block volume of
/// the spec, and appending rather than prepending the seed is what keeps it
/// that way. A firmware boot picks the first bootable disk, and a seed that
/// came first would be a VM that tries to boot off a 1 MiB FAT volume with no
/// bootloader on it.
///
/// Read-only, and that is not tidiness: the seed is derived from the spec and
/// rewritten on every provision, so a guest that wrote to it would be a guest
/// whose changes vanish at the next re-provision without anybody being told.
pub(crate) fn disks(spec: &InstanceSpec) -> Vec<serde_json::Value> {
    let mut disks: Vec<serde_json::Value> = spec.volumes.iter().filter_map(disk_config).collect();
    if let Some(seed) = &spec.cloud_init_seed {
        // Raw for the same reason the volumes are, and stated for the same
        // reason: a FAT12 image is raw, and an unstated type is a deprecation
        // warning per boot.
        disks.push(serde_json::json!({
            "path": seed,
            "readonly": true,
            "image_type": "Raw",
        }));
    }
    disks
}

/// One entry of CH's `fs` array: virtiofsd is already listening on `socket`,
/// and `tag` is the name the guest mounts (`mount -t virtiofs <tag> /mnt`).
/// `num_queues` and `queue_size` are CH's own defaults and are left to it.
pub(crate) fn fs_config(volume: &VolumeAttachment) -> Option<serde_json::Value> {
    match volume {
        VolumeAttachment::FsShare { socket, tag, .. } => {
            Some(serde_json::json!({ "socket": socket, "tag": tag }))
        }
        _ => None,
    }
}

pub(crate) fn build_vm_config(
    spec: &InstanceSpec,
    console_path: &PathBuf,
    serial_socket: &PathBuf,
) -> hypervisor::Result<serde_json::Value> {
    // `memory.shared` is a property of the VM, not of one kind of attachment:
    // any vhost-user backend maps guest memory, and a vhost-user-blk volume
    // needs it exactly as much as a gpu device does. Asking both halves of
    // the spec the same question is what keeps a storage backend from
    // silently getting a VM whose memory it cannot map.
    let has_vhost_user = spec
        .devices
        .iter()
        .any(DeviceAttachment::needs_shared_memory)
        || spec
            .volumes
            .iter()
            .any(|v| v.attachment.needs_shared_memory());

    // handle optional kernel & initramfs for direct-kernel boot, not required for UEFI boot
    let payload = match &spec.boot {
        BootSource::DirectKernel {
            kernel,
            cmdline,
            initramfs,
        } => {
            let mut p = serde_json::json!({ "kernel": kernel, "cmdline": cmdline });
            if let Some(i) = initramfs {
                p["initramfs"] = serde_json::json!(i);
            }
            p
        }
        BootSource::Firmware { firmware } => serde_json::json!({ "firmware": firmware }),
    };

    let mut config = serde_json::json!({
        "cpus":   { "boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus },
        "memory": {
            "size": spec.memory_mib * 1024 * 1024,
            "shared": has_vhost_user,
        },
        "payload": payload,
        "disks":  disks(spec),
        // The two guest devices, and they are configured differently on
        // purpose. `console` (virtio, hvc0) keeps writing straight to a file:
        // nothing is in that path, so nothing can break it. `serial` (the
        // UART, ttyS0) is where a guest booted with `console=ttyS0` actually
        // talks, so it is the one worth being able to type into — and a
        // device has exactly one mode, so it becomes a socket and the AGENT
        // writes the file from it. CH holds a 1 MiB ring while nobody is
        // connected and replays it, which is what makes that safe.
        "console": { "mode": "File", "file": console_path },
        "serial": { "mode": "Socket", "socket": serial_socket }

    });

    let shares: Vec<_> = spec
        .volumes
        .iter()
        .filter_map(|v| fs_config(&v.attachment))
        .collect();
    if !shares.is_empty() {
        config["fs"] = shares.into();
    }

    if !spec.nics.is_empty() {
        config["net"] = spec
            .nics
            .iter()
            .map(|n| {
                let mut net = serde_json::json!({ "tap": n.tap_name, "mac": n.mac.to_string() });
                // virtio-net's own MTU feature (VIRTIO_NET_F_MTU). The tap and
                // the bridge bound what the host forwards; this is the only way
                // the GUEST finds out, and without it an overlay VM emits
                // 1500-byte frames into a 1450-byte path and they vanish. Omitted
                // where nobody named one, so a plain VM's config is byte-identical
                // to what it has always been.
                if let Some(mtu) = n.mtu {
                    net["mtu"] = serde_json::Value::from(mtu);
                }
                net
            })
            .collect::<Vec<_>>()
            .into();
    }

    let mut vhost_user_devices = Vec::new();
    let mut vfio_devices = Vec::new();
    for dev in &spec.devices {
        match dev {
            DeviceAttachment::VhostUser {
                socket,
                device_type,
                queue_sizes,
                ..
            } => {
                vhost_user_devices.push(serde_json::json!({
                    "socket": socket,
                    "device_type": device_type,
                    "queue_sizes": queue_sizes,
                }));
            }
            DeviceAttachment::VfioPci { sysfs_path } => {
                vfio_devices.push(serde_json::json!({ "path": sysfs_path }));
            }
            other => {
                return Err(HypervisorError::InvalidSpec(format!(
                    "attachment type not yet supported by CH driver: {other:?}"
                )));
            }
        }
    }
    if !vhost_user_devices.is_empty() {
        config["generic_vhost_user"] = vhost_user_devices.into();
    }
    if !vfio_devices.is_empty() {
        config["devices"] = vfio_devices.into();
    }
    Ok(config)
}
