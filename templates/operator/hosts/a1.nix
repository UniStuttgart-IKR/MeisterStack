# SPDX-License-Identifier: MIT
# Host-specific hardware and filesystem configuration.
{ config, lib, pkgs, ... }:
{
  # boot.initrd.availableKernelModules = [ "nvme" "xhci_pci" "ahci" ];
  # boot.kernelModules = [ "kvm-amd" ];
  # hardware.cpu.amd.updateMicrocode = true;

  # Bind the installation device by its stable by-id path.
  # The serial alone does not determine the complete path.
  # disko.devices.disk.main.device = "/dev/disk/by-id/nvme-SAMSUNG_MZ..._S6PENX0T123456";

  # These mounts describe an existing installation. Remove them when install.layout
  # provides the same mounts through disko.
  fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
  fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
}
