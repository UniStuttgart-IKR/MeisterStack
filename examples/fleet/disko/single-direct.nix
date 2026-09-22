# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# One disk, one filesystem, no boot partition — for a guest whose hypervisor
# hands it kernel, initrd and command line (`boot = "direct"`).
#
# The worked example's copy of templates/operator/disko/single-direct.nix.
# There is no ESP in here on purpose: a direct-boot guest never reads a boot
# menu, so a partition for one would be a partition nothing writes to. The
# root partition carries the label `nixos` because the command line the
# provider loads is what has to find it.
{
  meisterstack.install.hasEsp = false;

  disko.devices.disk.main = {
    type = "disk";
    content = {
      type = "gpt";
      partitions = {
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
