# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A repository that is NOT ours, running MeisterStack.
#
# No image and no vendored module: somebody's own flake calls
# `meisterstack.lib.mkFleet`, takes the MODULE LIST of one host out of it and
# puts it into a `nixosSystem` of their own, next to their hardware, their
# stateVersion and their firewall. That is the second road into these modules
# — the other is the generic appliance image — and `nix flake check` in the
# repository above evaluates exactly this file, so the export cannot quietly
# stop standing on its own.
#
#   nix build .#nixosConfigurations.box.config.system.build.toplevel
#
# The certificates are the one thing that does not come from here:
# `meisterstack.pki.dir` is filled by `meister-deploy keys deliver`, and until
# it is, the units stay visibly skipped rather than restarting every two
# seconds.
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
          # The operator's half, and every line of it is a decision about a
          # MACHINE rather than about MeisterStack. Deliberately NOT our
          # answers: `stateVersion` is 24.11 where ours would be 25.11, and
          # the firewall is ON where nix/appliance.nix turns it off. The
          # check in the repository above fails the moment one of our modules
          # starts deciding either of them again (V03).
          profiles.base = { config, ... }: {
            system.stateVersion = "24.11";

            networking.firewall.enable = true;
            # `meisterstack.ports` is an ANSWER and not a mechanism: the
            # modules open nothing, they say which numbers they listen on,
            # and the host's own rule names them.
            networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
              cloud.api
              cloud.grpc
              cluster.api
              cluster.grpc
            ];

            # The signing key whose closures this host accepts (M0 probe
            # S12). An example name: a fleet that is really deployed names
            # the public half of its own.
            meisterstack.managed.trustedPublicKeys = [
              "foreign-example-not-a-real-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ];

            # And anything the binaries take, straight through. Nothing here
            # validates a key — the binaries do that at start-up.
            meisterstack.cloud.settings.metrics_listen = "0.0.0.0:9100";
          };
        };
    in
    {
      nixosConfigurations.box = nixpkgs.lib.nixosSystem {
        # The module list of that host, plus this machine's own facts. The
        # reason this road exists at all: a box with an NVIDIA card, a
        # Mellanox firmware and a hardware-configuration.nix generated on the
        # metal keeps all of it and is still a host of this fleet.
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
