# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# nix/tests/install-direct.nix' copy of
# templates/operator/disko/single-direct.nix: one disk, one ext4 filesystem
# labelled `nixos`, and no boot partition at all.
#
# A copy and not an import, because that is what an operator has: the
# template writes this file into their repository and it becomes theirs.
#
# The DEVICE is not in here: hosts/n1.nix binds it.
{
  # No ESP, and the inventory module holds `boot = "direct"` to exactly that.
  meisterstack.install.hasEsp = false;

  disko.devices.disk.main = {
    type = "disk";
    # Set in hosts/<id>.nix:
    #   disko.devices.disk.main.device = "/dev/disk/by-id/virtio-<serial>";
    content = {
      type = "gpt";
      partitions = {
        root = {
          size = "100%";
          content = {
            type = "filesystem";
            format = "ext4";
            mountpoint = "/";
            # The label a direct-boot command line can name
            # (`root=LABEL=nixos`), for a guest whose disk lands on whichever
            # bus the hypervisor chose that day.
            extraArgs = [ "-L" "nixos" ];
          };
        };
      };
    };
  };
}
