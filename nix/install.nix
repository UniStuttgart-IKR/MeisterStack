# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The installer MEDIUM of one host — and it is a medium, not the host.
#
# What comes out of here is the module that `lib.mkFleet` puts into
# `image.modules.iso-installer`, which is the sub-evaluation `nixos/modules/
# image/images.nix` builds the ISO from. It has to be there and not in the
# host itself: `isoImage.*` are options of the IMAGE, and setting one on a
# host is an option that does not exist (M0 finding A10, an hour of somebody's
# life).
#
# Three things this medium is:
#
#  1. **It carries the system it installs.** `isoImage.storeContents` puts the
#     target's toplevel AND the target's `diskoScript` into the ISO's store,
#     so the machine can be partitioned and installed with no network, no
#     substituter and no evaluation — the medium does not even have the
#     operator's flake. Measured in M0 (probe S5): the closure of the target
#     costs about 12 MiB on top of a 1.45 GiB installer, because an installer
#     already carries nearly the same store.
#
#  2. **It knows which machine it is for, and says so.**
#     `/etc/meister-install/target.json` names the fleet, the host, the boot
#     mode, the toplevel, the disko script, the layout, the disk (serial, wwn,
#     size) and what a reinstall must not touch. `meister-install confirm`
#     reads it and refuses anything that does not match. There is NO
#     `release_id` in it: an ISO derivation is fixed before a release exists,
#     and the honest back-reference is the toplevel path.
#
#  3. **It installs nothing by itself.** No unit, no timer, no autostart (D9).
#     A medium that formats a disk because somebody left it in a drive is the
#     exact failure this whole verb exists to prevent. What happens is that a
#     person reads `/etc/issue`, types one command with the disk's serial in
#     it, and gets a summary to confirm.
#
# And one thing it carries no matter what: **no secret**. The ISO is a file
# that travels — a USB stick, a BMC's virtual media, an http server — and
# anybody who holds it can read every byte. `install.authorized_keys` is the
# only key material in here and it is PUBLIC halves, put there so that a
# head-less machine can be reached at all; with an empty list this medium has
# no sshd, and the console is the way in. `checks.installer-no-secrets`
# measures the claim rather than trusting this paragraph.
{ id, host, target, fleet }:

{ config, pkgs, lib, ... }:

let
  install = host.install;

  # The same mapping nix/lib/manifest.nix uses. Written out rather than
  # imported, because it is three words and an import would be a file this
  # module reads for a string.
  unitOf = role: if role == "agent" then "meister-agent" else "meister-${role}-controller";

  keys = install.authorized_keys or [ ];
  reachable = keys != [ ];

  # What `meister-install confirm` is told about the machine it is standing
  # on. A file and not a command line: an operator types a serial, and
  # everything else has to be something the MEDIUM knows, or the check that
  # the serial is the right disk would be a check against what the same
  # person just typed.
  targetJson = {
    schema = "meister-deploy/install-target/1";
    fleet = fleet.name;
    host = id;
    boot_mode = host.boot;
    toplevel = "${target.system.build.toplevel}";
    disko_script = "${target.system.build.diskoScript}";
    layout = install.layout;
    disk = {
      serial = install.disk.serial;
      wwn = install.disk.wwn or null;
      size_bytes =
        if install.disk ? size_gb then install.disk.size_gb * 1000000000
        else throw "host ${id}: install.disk has no size_gb";
    };
    # Every block device the LAYOUT names, as the host's module bound it.
    #
    # Not in the brief's list and here on purpose: the installer is given a
    # SERIAL and has to end up at the device the partition table will be
    # written to, and the two are bound by a name only the host module knows
    # (`/dev/disk/by-id/nvme-<model>_<serial>` on one transport,
    # `virtio-<serial>` on another — M0 probe S7). The alternative was to
    # read the device out of the disko SCRIPT, which is grepping a shell
    # script for a path, and the one time that goes wrong is the time it
    # formats the wrong disk.
    layout_devices = lib.mapAttrsToList (_: d: d.device) (target.disko.devices.disk or { });
    preserve = install.preserve or [ ];
    # What the preserved paths live ON. `preserve` is a list of paths and
    # `meister-install` has to decide whether each one is on the disk it is
    # about to destroy; a path alone cannot answer that, and the answer is
    # in the inventory the operator wrote.
    persistence = map
      (p: {
        inherit (p) path;
        device_ref = p.device;
        required = p.required or true;
      })
      (host.persistence or [ ]);
  };
in
{
  # The target's system and the target's partition table, in the medium's
  # store. Two paths, and they are the whole reason this ISO is bigger than
  # an installer from nixpkgs.
  isoImage.storeContents = [
    target.system.build.toplevel
    target.system.build.diskoScript
  ];

  # `meister-install` is the third binary of the meister-deploy crate and
  # comes with the same package the fleet's units use. `openssh` is named
  # because the installer generates the host's first ssh key and prints its
  # fingerprint — and with no sshd on this medium nothing else would put
  # `ssh-keygen` on the path.
  environment.systemPackages = [
    config.meisterstack.package
    pkgs.openssh
  ];

  environment.etc."meister-install/target.json" = {
    text = builtins.toJSON targetJson + "\n";
    mode = "0444";
  };

  # What a person sees before they log in. The disk's serial is in it,
  # because the one mistake this medium has to make impossible is being
  # booted on the wrong machine and installing anyway.
  environment.etc.issue = lib.mkForce {
    text = ''

      MeisterStack installer for the host ${id} of the fleet ${fleet.name}.

      This medium installs ${id} onto the disk with serial ${install.disk.serial}
      (${toString (targetJson.disk.size_bytes / 1000000000)} GB, boot mode ${host.boot}).

      NOTHING HAPPENS UNTIL YOU RUN:

          meister-install confirm --host ${id} --disk ${install.disk.serial}

      It will show you the disk, the size and the model it found, and what it
      is about to destroy, before it does anything. ${
        if install.preserve or [ ] == [ ]
        then "This host preserves no paths across a reinstall."
        else "These paths must not be on that disk: "
             + lib.concatStringsSep ", " install.preserve + "."
      }
      Afterwards it prints the new host key's SHA256 fingerprint. Write it
      down: it is what `meister-deploy keys enroll ${id} --fingerprint ...`
      needs, and reading it off this console is the whole point of it.

    '';
    mode = "0444";
  };

  # Where `meister-install` mounts a partition for a moment while it looks
  # for an installation mark. Shipped rather than made on the spot, so that
  # `meister-install confirm --dry-run` — which writes nothing at all — can
  # still look.
  systemd.tmpfiles.rules = [ "d /run/meister-install/probe 0700 root root -" ];

  # The way in, or the absence of one.
  #
  # nixpkgs' installation-device profile turns sshd on with
  # `PermitRootLogin = "yes"` and a root account whose password is empty. On
  # a medium that carries a fleet's target configuration that is a machine
  # anybody on the network can walk into, so it is decided here instead: an
  # sshd exists only where the inventory named public keys for it, and root
  # can never log in with a password either way.
  #
  # `mkForce` on the login policy and not `mkDefault`: nix/managed.nix says
  # `prohibit-password` and the installation profile says `yes`, both as
  # defaults, and two defaults are a conflict rather than a precedence.
  services.openssh.enable = lib.mkForce reachable;
  services.openssh.settings.PermitRootLogin = lib.mkForce "prohibit-password";
  users.users.root.openssh.authorizedKeys.keys = keys;

  # The medium is not the host, so the host's units do not start on it.
  #
  # They are IN the image — it carries the target's whole closure — but a
  # cloud controller that comes up on an installer would bind ports, write
  # state and look for certificates that are not there yet, and a failed unit
  # on a console is noise in front of the one sentence somebody is meant to
  # read. `mkForce []` rather than `enable = false`: the units are declared
  # by role and what is wrong here is only that something wants them.
  #
  # Which units exist is read off the TARGET's configuration and not off
  # this one. Asking `config.systemd.services ? <name>` inside a definition
  # of `systemd.services` is a definition that reads itself, and the module
  # system says so with an infinite recursion — measured, the first time this
  # file was written.
  systemd.services = lib.mkMerge (
    map (role: { ${unitOf role}.wantedBy = lib.mkForce [ ]; }) target.meisterstack.unitsFor
    ++ lib.optional target.meisterstack.etcd.enable { etcd.wantedBy = lib.mkForce [ ]; }
  );

  # An installer gets its address from the network it is plugged into, and
  # the host's own static address belongs to the host. Without this the
  # medium would come up on the address the fleet expects the INSTALLED
  # machine at — which is the address somebody may still be talking to the
  # old machine on.
  networking.interfaces = lib.mkForce { };
}
