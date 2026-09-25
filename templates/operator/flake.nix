# SPDX-License-Identifier: MIT
# A MeisterStack deployment. This file is yours: change it.

{
  description = "A MeisterStack fleet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    # Pin MeisterStack to a revision before deployment.
    # Example: meisterstack.url = "github:UniStuttgart-IKR/MeisterStack/<rev>";
    meisterstack.url = "github:UniStuttgart-IKR/MeisterStack";
    meisterstack.inputs.nixpkgs.follows = "nixpkgs";

    # Use the stack's disko input for installation layouts.
    disko.follows = "meisterstack/disko";

    # Optional GPU input; CPU-only fleets do not need it.
    # leandro.url = "github:…/Leandro";
    # leandro.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, meisterstack, disko, ... }@inputs:
    let
      # Pass the optional GPU input to profiles.
      leandro = inputs.leandro or null;

      fleet = meisterstack.lib.mkFleet
        {
          inherit nixpkgs meisterstack disko leandro;
        }
        {
          # Who is in this fleet, and what each host is.
          inventory = ./fleet.toml;

          # Host policy: stateVersion, filesystems, firewall and SSH.
          profiles = import ./profiles.nix { inherit (nixpkgs) lib; inherit leandro; };
        };
    in
    fleet // {
      # Merge site checks with generated configuration and inventory checks.
      checks.x86_64-linux = fleet.checks.x86_64-linux
        // import ./tests/default.nix { inherit nixpkgs fleet; };
    };
}
