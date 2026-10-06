# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate a store-built host with OpenNebula provider initialization and no
# boot renderer: the provider unit runs the strict reader, nothing renders a
# config file at boot, and a static interface address turns provider networking
# off by default (W1).
{ nixpkgs, lib, pkgs, system, self }:

let
  hostOf = extra: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        networking.hostName = "probe";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.store-host
      self.nixosModules.provider-opennebula
      {
        meisterstack.roles = [ "agent" ];
        meisterstack.storeHost.enable = true;
      }
      extra
    ];
  }).config;

  # The same host, plus the one line a host with a static management address has.
  withStatic = hostOf {
    networking.interfaces.eth0.ipv4.addresses =
      [{ address = "10.128.1.119"; prefixLength = 16; }];
  };
  withoutStatic = hostOf { };

  failed = lib.filter (a: !a.assertion) withoutStatic.assertions;
  units = withoutStatic.systemd.services;
  unit = units.meister-provider-context or null;

  bad =
    map (a: "an assertion of a store-built host with a provider fails: ${a.message}") failed
    ++ lib.optional (unit == null)
      "a store-built host with nixosModules.provider-opennebula has no meister-provider-context unit"
    ++ lib.optional
      (unit != null && !(lib.hasInfix "context.sh" unit.script))
      "the unit of that host does not run the strict reader"
    ++ lib.optional (units ? meister-context)
      "a store-built host got the boot renderer, which is the one thing it must never have"
    ++ lib.optional withoutStatic.meisterstack.context.enable
      "meisterstack.context.enable is true on a store-built host"
    # W1: the default is a reading of what the host says, not a constant.
    ++ lib.optional withStatic.meisterstack.provider.opennebula.network
      ("a host that names a static address for eth0 still has "
      + "provider.opennebula.network on by default: two owners for one "
      + "interface")
    ++ lib.optional (lib.filter (a: !a.assertion) withStatic.assertions != [ ])
      "a store-built host with a static address and a provider does not evaluate"
    ++ lib.optional (!withoutStatic.meisterstack.provider.opennebula.network)
      ("a host that names NO address has provider.opennebula.network off: "
      + "then nothing configures the interface and the VM comes up "
      + "unreachable");
in
pkgs.runCommand "provider-opennebula-reads-its-context" { } (
  if bad == [ ] then ''
    echo "a store-built host reads its provider and renders nothing at boot"
    touch $out
  '' else ''
    ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
    echo "-> nix/roles.nix declares providerScript, nix/services.nix runs it (lane 5C)"
    exit 1
  ''
)
