# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Compare a bare host with role-free and agent-role imports. Runtime modules
# must preserve host-global boot and network policy; role-free imports also
# leave optional daemons, kernel modules, and mounts unchanged.
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
