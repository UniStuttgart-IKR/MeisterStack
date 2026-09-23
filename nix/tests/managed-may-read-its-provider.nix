# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A managed host may read its provider without becoming an appliance.
#
# The shape the lab needed (L2 finding N5, 2026-09-23): a managed NixOS host
# on an OpenNebula VM. Its config files are a system generation, so it must
# not have the boot renderer — nix/managed.nix asserts against it. But where
# the machine was BOOTED is still the provider's to say, and without an
# address, a route and a resolver nothing reaches it at all.
#
# `meisterstack.context.providerScript` used to be declared by the renderer,
# so `nixosModules.provider-opennebula` could not be imported without it and
# the combination did not evaluate. The operator's repository carried thirty
# hand-written lines of unit instead.
#
# Three claims, and all three are module-system values rather than a booted
# machine — which is where the bug was:
#
#   1. managed + provider-opennebula evaluates, and every assertion of the
#      resulting host holds (the renderer is not there, so managed's own
#      assertion is satisfied).
#   2. The strict reader's script really lands in a unit of that host.
#   3. That host renders nothing at boot: no `meister-context.service`.
#
# And a fourth, from the lab (L4 finding W1, 2026-09-23): the module answers
# the ONE-owner question itself. A host that names a static address owns its
# interface, and a host that names none lets the medium own it. With a flat
# `network = true` default every managed host that named its address in the
# inventory — which is every controller of a real fleet — stopped at
# `resolve` with the assertion below, and an operator repository had to carry
# a module whose only job was to set a default nobody disagrees with.
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
      self.nixosModules.managed
      self.nixosModules.provider-opennebula
      {
        meisterstack.roles = [ "agent" ];
        meisterstack.managed.enable = true;
        meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
      }
      extra
    ];
  }).config;

  # The same host, plus the one line an inventory writes for a host with a
  # static management address.
  withStatic = hostOf {
    networking.interfaces.eth0.ipv4.addresses =
      [{ address = "10.128.1.119"; prefixLength = 16; }];
  };
  withoutStatic = hostOf { };

  probe = (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        networking.hostName = "probe";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.managed
      self.nixosModules.provider-opennebula
      {
        meisterstack.roles = [ "agent" ];
        meisterstack.managed.enable = true;
        meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
      }
    ];
  }).config;

  failed = lib.filter (a: !a.assertion) probe.assertions;
  units = probe.systemd.services;
  unit = units.meister-provider-context or null;

  bad =
    map (a: "an assertion of a managed host with a provider fails: ${a.message}") failed
    ++ lib.optional (unit == null)
      "a managed host with nixosModules.provider-opennebula has no meister-provider-context unit"
    ++ lib.optional
      (unit != null && !(lib.hasInfix "context.sh" unit.script))
      "the unit of that host does not run the strict reader"
    ++ lib.optional (units ? meister-context)
      "a managed host got the boot renderer, which is the one thing it must never have"
    ++ lib.optional probe.meisterstack.context.enable
      "meisterstack.context.enable is true on a managed host"
    # W1: the default is a reading of what the host says, not a constant.
    ++ lib.optional withStatic.meisterstack.provider.opennebula.network
      ("a host that names a static address for eth0 still has "
        + "provider.opennebula.network on by default: two owners for one "
        + "interface, and the assertion stops `resolve` for every controller "
        + "of a real fleet")
    ++ lib.optional (lib.filter (a: !a.assertion) withStatic.assertions != [ ])
      "a managed host with a static address and a provider does not evaluate"
    ++ lib.optional (!withoutStatic.meisterstack.provider.opennebula.network)
      ("a host that names NO address has provider.opennebula.network off: "
        + "then nothing configures the interface and the VM comes up "
        + "unreachable");
in
pkgs.runCommand "managed-may-read-its-provider" { } (
  if bad == [ ] then ''
    echo "a managed host reads its provider and renders nothing at boot"
    touch $out
  '' else ''
    ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
    echo "-> nix/roles.nix declares providerScript, nix/services.nix runs it (lane 5C)"
    exit 1
  ''
)
