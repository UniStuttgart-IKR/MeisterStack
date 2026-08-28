{
  description = "MeisterStack deploy tooling: control-plane VM image for the lab";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixos-generators }: {
    # One role-agnostic image for both control-plane VMs; the OpenNebula
    # context decides at boot whether it runs the cloud- or the
    # cluster-controller (CONTEXT: MEISTER_ROLE=cloud|cluster).
    packages.x86_64-linux.control-plane-image = nixos-generators.nixosGenerate {
      system = "x86_64-linux";
      format = "qcow";
      modules = [
        ./nix/base.nix
        ./nix/one-context.nix
        ./nix/etcd.nix
        ./nix/controllers.nix
        ./nix/agent.nix
      ];
    };
  };
}
