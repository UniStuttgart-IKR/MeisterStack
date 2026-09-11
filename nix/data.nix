# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The data block: one disk, and everything on this box that must survive an
# image swap lives on it under a name of its own.
#
# The lab has been mounting `/dev/disk/by-label/etcd-data` at /var/lib/etcd
# since etcd got a state worth keeping, and BY LABEL rather than by device
# name because which slot a disk lands in is not a promise anybody made —
# /dev/vdb quietly became sda+vda twice, and etcd lived on the root disk
# without saying so. That label still works and is still the default.
#
# What a box with four roles needs is one block for etcd AND the addons, so
# `meisterstack.data.label = "meister-data"` mounts it once at
# /var/lib/meister-data and gives each service a subdirectory. Two shapes, one
# rule: state is on a labelled block or it is on the root disk, and which one
# is a sentence somebody wrote down rather than a surprise.
{ lib, config, ... }:
let
  cfg = config.meisterstack.data;
  shared = cfg.label != "etcd-data";
in
{
  options.meisterstack.data = {
    label = lib.mkOption {
      type = lib.types.str;
      default = "etcd-data";
      example = "meister-data";
      description = ''
        The filesystem label of this box's data block. The default is the
        lab's historical one and mounts only /var/lib/etcd, exactly as before.
        Any other value mounts /var/lib/meister-data instead and puts etcd
        under `etcd/` and the addons under `addons/` there.

        The label is IN the filesystem (`mkfs.ext4 -L <label>`), so it
        survives an image swap and a bus surprise alike.
      '';
    };

    mountPoint = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/meister-data";
      internal = true;
      description = "Where the shared block is mounted.";
    };
  };

  config = lib.mkIf shared {
    fileSystems.${cfg.mountPoint} = {
      device = "/dev/disk/by-label/${cfg.label}";
      fsType = "ext4";
      # nofail, like the etcd mount it replaces: a box whose data block was
      # not attached should come up and say so, not drop into emergency mode.
      options = [ "nofail" "x-systemd.device-timeout=5s" ];
    };

    # etcd is pointed at its subdirectory rather than bind-mounted onto it: a
    # bind mount of a directory that does not exist yet is the kind of silent
    # nofail that put etcd on the root disk in the first place.
    services.etcd.dataDir = "${cfg.mountPoint}/etcd";
  };
}
