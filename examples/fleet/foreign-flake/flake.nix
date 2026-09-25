# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Import generated host modules into an existing NixOS configuration.
# Host policy remains local; service credentials are supplied outside the Nix store.
{
  description = "A NixOS host of somebody else's that runs MeisterStack";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    meisterstack.url = "path:../../..";
  };

  outputs = { self, nixpkgs, meisterstack }:
    let
      lib = nixpkgs.lib;

      fleet = meisterstack.lib.mkFleet
        {
          inherit nixpkgs;
          meisterstack = meisterstack;
        }
        {
          inventory = ./fleet.toml;
          # Use distinct host policy to test that imported modules do not override it.
          profiles.base = { config, ... }: {
            system.stateVersion = "24.11";

            networking.firewall.enable = true;
            # Choose firewall openings from the published service port numbers.
            networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
              cloud.api
              cloud.grpc
              cluster.api
              cluster.grpc
            ];

            # Placeholder public signing key; replace it before deployment.
            meisterstack.managed.trustedPublicKeys = [
              "foreign-example-not-a-real-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ];

            # Pass runtime settings through; binary configuration checks validate their shape.
            meisterstack.cloud.settings.metrics_listen = "0.0.0.0:9100";
          };
        };
    in
    {
      nixosConfigurations.box = nixpkgs.lib.nixosSystem {
        # Combine generated fleet modules with existing host hardware and filesystems.
        modules = fleet.hostModules.box ++ [
          {
            fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
            fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
            boot.kernelModules = [ "kvm-amd" ];
          }
        ];
      };
    };
}
