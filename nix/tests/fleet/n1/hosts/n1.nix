# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Virtual hardware fixture; inventory supplies the deployment identity.
{ ... }:
{
  # Include the drivers required to find the installed root filesystem.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "ahci"
    "sd_mod"
  ];

  # Bind the layout to the virtual disk's stable serial path.
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERDIRECT1";
}
