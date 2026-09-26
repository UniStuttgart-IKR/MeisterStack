# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Configure one host's installer image. It embeds the target closure, disko
# script, disk identity, and preservation metadata, allowing offline installation.
# Installation requires an explicit command; the image has no installer autostart.
# Only public SSH keys are embedded, and an empty key list disables SSH access.
{ id, host, target, fleet }:

{ config, pkgs, lib, ... }:

let
  install = host.install;

  # Map inventory boot modes to the installer contract.
  unitOf = role: if role == "agent" then "meister-agent" else "meister-${role}-controller";

  keys = install.authorized_keys or [ ];
  reachable = keys != [ ];

  # Describe the target independently of the operator's confirmation arguments.
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
    # Record the devices selected by the evaluated disk layout so confirmation
    # can compare them with the discovered disk identity.
    layout_devices = lib.mapAttrsToList (_: d: d.device) (target.disko.devices.disk or { });
    preserve = install.preserve or [ ];
    # Record which devices back preserved paths before evaluating a reinstall.
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
  # Include the target system and partitioning script in the installer store.
  isoImage.storeContents = [
    target.system.build.toplevel
    target.system.build.diskoScript
  ];

  # Provide the installer binary and ssh-keygen for initial host identity.
  environment.systemPackages = [
    config.meisterstack.package
    pkgs.openssh
  ];

  environment.etc."meister-install/target.json" = {
    text = builtins.toJSON targetJson + "\n";
    mode = "0444";
  };

  # Show the target and expected disk identity on the installation console.
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

  # Provide a temporary mountpoint for installation-marker inspection.
  systemd.tmpfiles.rules = [ "d /run/meister-install/probe 0700 root root -" ];

  # Enable SSH only with configured public keys; disable password authentication.
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
