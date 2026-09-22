# SPDX-License-Identifier: MIT
# One disk, one filesystem, no boot partition — for a guest whose hypervisor
# hands it kernel, initrd and command line (`boot = "direct"`).
#
# There is no ESP and no boot loader in here, and that is the whole point of
# the file: a direct-boot guest never reads a boot menu, so a partition for
# one would be a partition nothing ever writes to. What the machine needs is
# a root filesystem the kernel can find from the command line, which is why
# the partition carries the label `nixos`.
#
# The way FORWARD for such a host is the provider: `meister-deploy build`
# exports a bundle (kernel, initrd, cmdline) per direct host, and the
# provider loads it. The way BACK is the switch rollback, which is userland
# and works unchanged; there is no boot rollback here, because
# `bootctl set-oneshot` needs a boot menu (`meister-activate activate
# --mode boot` refuses on such a host, with that sentence).
#
# The DEVICE is not in here: it belongs to the host (hosts/<id>.nix binds it
# through /dev/disk/by-id by the disk's serial), because a layout is a shape
# and a device is a machine.
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
