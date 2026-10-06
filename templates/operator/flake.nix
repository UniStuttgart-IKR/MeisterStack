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

    # Optional GPU input; CPU-only fleets do not need it. Pin <rev> to the Leandro revision
    # that patches/README.md of the meisterstack input names: its cloud-hypervisor patch
    # series is the one this stack carries, both ends of the vhost-user channel must be on it,
    # and mkFleet refuses a leandro input on another series. Leandro tracks nixos-26.05 and
    # this template nixos-25.11, so do not add `follows` (the line below) before moving
    # nixpkgs to 26.05: it would build Leandro against a nixpkgs it was not written for.
    # leandro.url = "github:UniStuttgart-IKR/Leandro/<rev>";
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
