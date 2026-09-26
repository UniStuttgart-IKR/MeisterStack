# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# UEFI disk fixture: GPT, a 1 GiB ESP, and an ext4 root labelled nixos.
# The host module supplies the device; inventory selects this layout.
{
  # Declare the ESP for boot-mode validation.
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
            # The label base.nix' `fileSystems."/boot"` looks for.
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
