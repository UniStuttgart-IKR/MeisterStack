# SPDX-License-Identifier: MIT
# One NVMe: an EFI system partition and the rest as the root filesystem.
#
# Used by the first install (`meister-deploy install`, M3), which partitions
# with disko out of the layout the inventory's `install.layout` names. The
# DEVICE is not in here: it belongs to the host (hosts/<id>.nix binds it
# through /dev/disk/by-id by the disk's serial), because a layout is a shape
# and a device is a machine.
#
# Measured in M0 probe S6 against the pinned nixpkgs: `disko.devices` of this
# shape evaluates, and `fileSystems."/".device` comes out as
# /dev/disk/by-partlabel/disk-main-root.
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
