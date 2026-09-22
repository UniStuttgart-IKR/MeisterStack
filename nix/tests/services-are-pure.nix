# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `nixosModules.services` decides nothing about the machine, and this is what
# holds it to that.
#
# A minimal host is evaluated three times — without our modules, with them and
# no role, and with them and the agent role — and the attributes below have to
# come out the same. They are not a taste: each one is a decision somebody
# else's NixOS configuration has already made. A module that sets
# `stateVersion`, turns a firewall off or names a bootloader cannot be
# imported into a host that is not ours, and `nixosModules.default` is exactly
# that import.
#
# With no role the list is longer, because a machine that carries no unit of
# ours should carry no etcd, no collector, no routing daemon, no kernel module
# and no mount of ours either.
#
# Lane 1A wrote this check; 1B moved it out of flake.nix unchanged, so that
# the flake reads as a list of outputs rather than as a test suite.
{ nixpkgs, lib, pkgs, system, self }:

  let
    probe = modules: (nixpkgs.lib.nixosSystem {
      modules = [{ nixpkgs.hostPlatform = system; }] ++ modules;
    }).config;

    bare = probe [ ];
    noRole = probe [ self.nixosModules.services ];
    agentRole = probe [
      self.nixosModules.services
      { meisterstack.roles = [ "agent" ]; }
    ];

    hostGlobal = c: {
      "networking.useDHCP" = c.networking.useDHCP;
      "networking.firewall.enable" = c.networking.firewall.enable;
      "networking.resolvconf.enable" = c.networking.resolvconf.enable;
      "networking.usePredictableInterfaceNames" =
        c.networking.usePredictableInterfaceNames;
      "nix.enable" = c.nix.enable;
      "system.stateVersion" = c.system.stateVersion;
      "boot.kernelParams" = c.boot.kernelParams;
      "boot.loader.grub.enable" = c.boot.loader.grub.enable;
      "boot.loader.grub.device" = c.boot.loader.grub.device;
      "boot.loader.systemd-boot.enable" = c.boot.loader.systemd-boot.enable;
      "boot.loader.efi.canTouchEfiVariables" =
        c.boot.loader.efi.canTouchEfiVariables;
    };

    roleLess = c: hostGlobal c // {
      "services.etcd.enable" = c.services.etcd.enable;
      "services.alloy.enable" = c.services.alloy.enable;
      "services.frr.bgpd.enable" = c.services.frr.bgpd.enable;
      "boot.kernelModules" = c.boot.kernelModules;
      "fileSystems" = lib.attrNames c.fileSystems;
    };

    differing = f: a: b:
      lib.filter (k: (f a).${k} != (f b).${k}) (lib.attrNames (f a));

    bad =
      map (k: "with no role, ${k} is not what it was") (differing roleLess bare noRole)
      ++ map (k: "with the agent role, ${k} is not what it was")
        (differing hostGlobal bare agentRole);
  in
  pkgs.runCommand "services-are-pure" { } (
    if bad == [ ] then ''
      echo "nixosModules.services changed nothing host-global, with and without a role"
      touch $out
    '' else ''
      ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
      echo "-> nix/services.nix decides only what MeisterStack is, never what the machine is"
      exit 1
    ''
  )
