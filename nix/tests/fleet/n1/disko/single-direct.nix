# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Direct-boot disk fixture: GPT and an ext4 root labelled nixos, without an ESP.
# The host module supplies the device; inventory selects this layout.
{
  # Declare the absence of an ESP for boot-mode validation.
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
            # Keep the root label stable across virtual disk buses.
            extraArgs = [ "-L" "nixos" ];
          };
        };
      };
    };
  };
}
