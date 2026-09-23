# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# /etc/resolv.conf has one author, and on a managed host with a provider
# script that author is the provider.
#
# Why this is a check and not a comment (lab lane L2, 2026-09-23): a managed
# host reading an OpenNebula CONTEXT cd wrote ETH0_DNS into
# /etc/resolv.conf, resolvconf refused the file it had not signed
# ("signature mismatch"), `network-setup.service` failed, and the
# `switch-to-configuration` around it exited 4 — which failed the ACTIVATION
# and then failed its ROLLBACK with the same sentence. The host ended in
# `recovery-required`. nix/appliance.nix has had `resolvconf.enable = false`
# since 2026-09-08 for the same reason; nix/managed.nix did not.
#
# Two probes, because the fix has two halves and both are promises:
#
#   with a provider script     resolvconf steps aside (false)
#   without one                managed decides nothing, and the value is
#                              whatever the bare machine had
#
# Evaluation only: nothing is built, no VM is started. What is asserted is a
# module-system value, and that is where the bug was.
{ nixpkgs, lib, pkgs, system, self }:

let
  probe = modules: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        networking.hostName = "probe";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
    ] ++ modules;
  }).config;

  managedModules = [
    self.nixosModules.services
    self.nixosModules.managed
    {
      meisterstack.roles = [ "agent" ];
      meisterstack.managed.enable = true;
      meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
    }
  ];

  bare = probe [ ];
  quiet = probe managedModules;
  withProvider = probe (managedModules ++ [
    { meisterstack.context.providerScript = "echo the provider writes the resolver"; }
  ]);

  bad =
    lib.optional (withProvider.networking.resolvconf.enable != false)
      ("a managed host whose provider script writes /etc/resolv.conf still has "
        + "resolvconf enabled: two authors for one file, which is an activation "
        + "that fails and a rollback that fails with it")
    ++ lib.optional
      (quiet.networking.resolvconf.enable != bare.networking.resolvconf.enable)
      ("a managed host with no provider script changed networking.resolvconf.enable "
        + "from ${lib.boolToString bare.networking.resolvconf.enable} to "
        + "${lib.boolToString quiet.networking.resolvconf.enable}: this profile "
        + "decides the resolver only where something else already writes it");
in
pkgs.runCommand "one-resolver-author" { } (
  if bad == [ ] then ''
    echo "a provider script turns resolvconf off, and nothing else does"
    touch $out
  '' else ''
    ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
    echo "-> /etc/resolv.conf has one author (nix/managed.nix, lane 5C)"
    exit 1
  ''
)
