# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Evaluate resolver ownership: provider scripts disable resolvconf by default;
# without a provider the managed module leaves the host's choice unchanged.
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
