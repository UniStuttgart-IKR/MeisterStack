# SPDX-License-Identifier: MIT
# Direct-boot layout: labelled ext4 root, no ESP or in-guest bootloader.
# The provider supplies kernel, initrd and command line. Bind the device in the host module.
{
  # Must match boot = "direct" in the inventory.
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
            # Let the provider command line locate root by label.
            extraArgs = [ "-L" "nixos" ];
          };
        };
      };
    };
  };
}
