# SPDX-License-Identifier: MIT
# UEFI layout: a 1 GiB ESP and ext4 root on the remaining space.
# Bind the device in the host module; install.layout selects this file.
{
  # Must match the inventory boot mode.
  meisterstack.install.hasEsp = true;

  disko.devices.disk.main = {
    type = "disk";
    # Set in hosts/<id>.nix:
    #   disko.devices.disk.main.device = "/dev/disk/by-id/nvme-…_<serial>";
    content = {
      type = "gpt";
      partitions = {
        ESP = {
          size = "1G";
          type = "EF00";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            # Label for the EFI system partition.
            extraArgs = [ "-n" "ESP" ];
          };
        };
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
            extraArgs = [ "-L" "nixos" ];
          };
        };
      };
    };
  };
}
