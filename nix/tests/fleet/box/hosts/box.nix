# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The machine `box` of nix/tests/install.nix, which is a virtual one.
{ ... }:
{
  # What a `hardware-configuration.nix` carries, which on a virtual machine
  # is one line: the drivers its initrd needs to SEE the disk.
  #
  # Measured, not guessed: without them the machine booted from its own disk
  # with the right `init=` on the command line, waited 22 seconds for a root
  # filesystem that no driver could find, and panicked with "Attempted to
  # kill init". The installer medium does not have this problem
  # (`hardware.enableAllHardware` puts every driver in ITS initrd), so the
  # install succeeds and the first boot is where it shows — which is exactly
  # the shape of this mistake on real metal.
  boot.initrd.availableKernelModules = [
    "virtio_pci"
    "virtio_blk"
    "virtio_scsi"
    "ahci"
    "sd_mod"
  ];

  # The disk the layout shapes. A virtio disk with a serial gets
  # /dev/disk/by-id/virtio-<serial> and no model in the name (M0 probe S7),
  # which is exactly why the installer compares this device with the serial
  # it was given instead of deriving one from the other.
  disko.devices.disk.main.device = "/dev/disk/by-id/virtio-MEISTERTEST01";
}
