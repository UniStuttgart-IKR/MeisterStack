# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Guard the legacy appliance path: nix/roles.nix bakes `meisterstack.roles` as
# MEISTER_ROLE into /etc/meisterstack/context.env, and the boot renderer of the
# lab's context VMs (meisterstack-lab legacy/nix/context.nix) reads it from
# there. The provider unit of this flake does not read that file.
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
      extra
    ];
  }).config;

  everyRole = hostOf {
    meisterstack.roles = [ "agent" "cluster" "cloud" ];
    meisterstack.cloud.settings.auth.chain = [ "mtls" ];
    # A value a shell would split, as a context default may carry one.
    meisterstack.context.defaults.MEISTER_LOKI_URL = "http://10.0.0.10:3100/a b";
  };
  noRole = hostOf { };

  envOf = c: c.environment.etc."meisterstack/context.env".source;
in
pkgs.runCommand "roles-context-env" { } ''
  env=${envOf everyRole}
  cat "$env"
  grep -qx 'MEISTER_ROLE=agent,cluster,cloud' "$env" \
    || { echo "-> the roles of the host are not MEISTER_ROLE in context.env"; exit 1; }
  grep -qx "MEISTER_LOKI_URL='http://10.0.0.10:3100/a b'" "$env" \
    || { echo "-> a context default is not one shell word in context.env"; exit 1; }
  ${lib.optionalString (noRole.environment.etc ? "meisterstack/context.env") ''
    echo "-> a host without roles and without context defaults got a context.env"
    exit 1
  ''}
  echo "the roles a host is built with reach the boot renderer as MEISTER_ROLE"
  touch $out
''
