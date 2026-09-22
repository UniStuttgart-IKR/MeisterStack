# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# One disk: an EFI system partition and the rest as the root filesystem.
#
# The worked example's copy of templates/operator/disko/single-nvme.nix.
# `lib.mkFleet` imports it into every host whose inventory entry names it in
# `install.layout`, and from then on disko is the only author of that host's
# `fileSystems` — which is why examples/fleet/profiles.nix sets none.
#
# The DEVICE is not in here: it belongs to the host (hw/<id>.nix binds it
# through /dev/disk/by-id), because a layout is a shape and a device is a
# machine.
{
  # An ESP, so a host that uses this layout boots itself: `boot = "uefi"`.
  meisterstack.install.hasEsp = true;

  disko.devices.disk.main = {
    type = "disk";
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
