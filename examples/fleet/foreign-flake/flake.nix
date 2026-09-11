# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A host that is NOT ours, running MeisterStack.
#
# No image, no fleet.toml, no meister-deploy: somebody's own NixOS
# configuration imports `nixosModules.default`, names its roles, and is a
# control plane. This is the third road into the same modules — the other two
# are the generic OpenNebula image and a planned node — and `nix flake check`
# in the repository above evaluates exactly this file, so the export cannot
# quietly stop standing on its own.
#
#   nix build .#nixosConfigurations.foreign.config.system.build.toplevel
#
# The certificates are the one thing that does not come from here:
# `/opt/meisterstack/pki` is filled by `meister-deploy keys push`, and until it
# is, the units stay visibly skipped rather than restarting every two seconds.
{
  description = "A NixOS host of somebody else's that runs MeisterStack";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    meisterstack.url = "path:../../..";
  };

  outputs = { self, nixpkgs, meisterstack }: {
    nixosConfigurations.foreign = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        meisterstack.nixosModules.default
        # What this host IS, in this fleet: written by
        # `meister-deploy render box -o box.nix` and nothing else. Roles, the
        # derived addresses, the issuer, the scrape list — a pure function of
        # fleet.toml, byte-identical on every render, and carrying nothing
        # about this machine's hardware.
        ./box.nix
        {
          networking.hostName = "foreign";
          system.stateVersion = "25.11";

          # And anything the binaries take, straight through. Nothing here
          # validates a key — the binaries do that at start-up. This is the
          # half the plan does not own.
          meisterstack.cloud.settings.listen_api = "0.0.0.0:3000";

          # Ordinary NixOS below this line — the host's own, and the reason
          # this road exists at all: a box with an NVIDIA card, a Mellanox
          # firmware and a hardware-configuration.nix generated on the metal
          # keeps all of it and is still a node of this fleet.
          fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
          boot.loader.grub.device = "/dev/vda";
        }
      ];
    };
  };
}
