# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Mount optional shared state storage by stable device reference. The runtime
# does not format it; an absent optional device permits root-filesystem fallback.
{ lib, config, ... }:
let
  cfg = config.meisterstack.data;
  # The historical label mounts only /var/lib/etcd (nix/etcd.nix); null mounts nothing.
  shared = cfg.label != null && cfg.label != "etcd-data";
in
{
  options.meisterstack.data = {
    label = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "etcd-data";
      example = "meister-data";
      description = ''
        The filesystem label of this box's data block. The default is the
        lab's historical one and mounts only /var/lib/etcd, exactly as before.
        Any other value mounts /var/lib/meister-data instead and puts etcd
        under `etcd/` and the addons under `addons/` there. `null` mounts
        nothing: etcd and the addons keep their state on the filesystem that
        holds /var/lib, and boot does not wait for a block that is not there.

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
      # Permit boot without the optional data device.
      options = [ "nofail" "x-systemd.device-timeout=5s" ];
    };

    # Point etcd directly at its data subdirectory.
    services.etcd.dataDir = "${cfg.mountPoint}/etcd";
  };
}
