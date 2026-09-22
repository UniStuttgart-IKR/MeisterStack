# SPDX-License-Identifier: MIT
# A MeisterStack deployment. This file is yours: change it.

{
  description = "A MeisterStack fleet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    # The stack. Pin it to a REVISION before you deploy anything twice:
    # a deployment names the tree it came from, and a branch is not a tree.
    #
    #   meisterstack.url = "github:UniStuttgart-IKR/MeisterStack/<rev>";
    #
    # `meister-deploy init --meisterstack <flakeref>` writes this line for
    # you; `nix flake update meisterstack` moves it on purpose.
    meisterstack.url = "github:UniStuttgart-IKR/MeisterStack";
    meisterstack.inputs.nixpkgs.follows = "nixpkgs";

    # Disk layouts for the first install. It follows the stack's pin so that
    # there is one disko in this repository and not two.
    disko.follows = "meisterstack/disko";

    # The GPU stack, for a fleet that has cards in it. Commented out on
    # purpose: a CPU-only fleet builds without it, and an input that is
    # declared is an input that has to be fetched.
    #
    # leandro.url = "github:…/Leandro";
    # leandro.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, meisterstack, disko, ... }@inputs:
    let
      fleet = meisterstack.lib.mkFleet
        {
          inherit nixpkgs meisterstack disko;
          # leandro = inputs.leandro or null;
        }
        {
          # Who is in this fleet, and what each host is.
          inventory = ./fleet.toml;

          # Your half: everything that is a decision about a MACHINE rather
          # than about MeisterStack — stateVersion, filesystems, firewall,
          # sshd. A host gets the profiles its inventory entry names.
          profiles = import ./profiles.nix { inherit (nixpkgs) lib; };
        };
    in
    fleet // {
      # Your own tests, next to the ones the fleet brings (`config-<id>`,
      # `inventory-parity`, `manifest-json`).
      checks.x86_64-linux = fleet.checks.x86_64-linux
        // import ./tests/default.nix { inherit nixpkgs fleet; };
    };
}
