# SPDX-License-Identifier: MIT
# The machine a1, and nothing about the fleet.
#
# This is where a `hardware-configuration.nix` generated on the metal goes —
# `nixos-generate-config --no-filesystems --show-hardware-config` on the box
# — together with a driver, a firmware, a kernel option or a disk layout.
# None of that is something a fleet tool should be trying to describe.
{ config, lib, pkgs, ... }:
{
  # boot.initrd.availableKernelModules = [ "nvme" "xhci_pci" "ahci" ];
  # boot.kernelModules = [ "kvm-amd" ];
  # hardware.cpu.amd.updateMicrocode = true;

  # The disk this host installs onto, bound by its SERIAL through
  # /dev/disk/by-id — never /dev/nvme0n1, which is a name the kernel hands
  # out in boot order. The layout itself is disko/single-nvme.nix, and the
  # inventory's `install.layout` is what names it.
  #
  # disko.devices.disk.main.device = "/dev/disk/by-id/nvme-SAMSUNG_MZ..._S6PENX0T123456";

  # …and until this host HAS an install table, it is a machine somebody else
  # partitioned, so it says where its root is itself. Delete these two lines
  # on the day `install` in fleet.toml names a layout: disko writes them
  # then, and two authors for one mount is one too many.
  fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
  fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
}
