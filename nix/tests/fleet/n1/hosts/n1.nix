# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The machine `n1` of nix/tests/install-direct.nix, which is a guest.
{ ... }:
{
  # What a `hardware-configuration.nix` carries: the drivers the initrd
  # needs to see the disk. A guest that boots direct needs them as much as
  # one that boots itself — more, in fact, because there is no boot menu to
  # notice the mistake from.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "ahci"
    "sd_mod"
  ];

  # The disk the layout shapes. A virtio disk with a serial gets
  # /dev/disk/by-id/virtio-<serial> (M0 probe S7).
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERDIRECT1";
}
