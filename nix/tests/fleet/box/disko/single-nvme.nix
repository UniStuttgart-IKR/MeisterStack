# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# nix/tests/install.nix' copy of templates/operator/disko/single-nvme.nix:
# one disk, an EFI system partition of 1G and the rest as the root
# filesystem.
#
# A copy and not an import, because that is what an operator has: the
# template writes this file into their repository and it becomes theirs. The
# test uses it the way `lib.mkFleet` uses any layout — imported into the host
# whose inventory entry names it in `install.layout`.
#
# The DEVICE is not in here: hosts/box.nix binds it.
{
  # This layout makes an ESP, so a host that uses it boots itself
  # (`boot = "uefi"` in the inventory). nix/lib/inventory.nix compares the
  # two and refuses the mismatch rather than installing a boot loader
  # nowhere.
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
