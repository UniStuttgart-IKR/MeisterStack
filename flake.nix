# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

{
  description = "MeisterStack: the service modules and the packages";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    # Neither is used by this flake any more: fleets, installers and images are
    # meister-deploy's. Both stay until ~/git/meisterstack-lab, which follows
    # `meisterstack/disko` and builds its appliance image through
    # `meisterstack.inputs.nixos-generators`, takes them from elsewhere.
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      # Instantiate the package set with the repository overlay.
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
      lib = nixpkgs.lib;

      # A store-built host of the service modules alone with `roles`, for the
      # checks that read what such a host is built from.
      storeHostOf = name: roles: (nixpkgs.lib.nixosSystem {
        modules = [
          self.nixosModules.services
          self.nixosModules.store-host
          {
            nixpkgs.hostPlatform = system;
            nixpkgs.overlays = [ self.overlays.default ];
            networking.hostName = name;
            system.stateVersion = "25.11";
            fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
            boot.loader.grub.device = "nodev";
            meisterstack.storeHost.enable = true;
            meisterstack.roles = roles;
          }
        ];
      }).config;
      # A control plane and an agent.
      storeHosts = {
        cp = storeHostOf "cp" [ "cloud" "cluster" ];
        n1 = storeHostOf "n1" [ "agent" ];
      };

    in
    {
      # Public module composition: services define runtime integration; store-host
      # takes binaries and complete config files from the system generation. Host
      # profiles retain machine policy; deployment transport is meister-deploy's.
      nixosModules = {
        services = ./nix/services.nix;
        # Binaries and complete config files from the system generation, without
        # any deployment transport.
        store-host = ./nix/store-host.nix;
        # Optional OpenNebula provider initialization, separate from the default module.
        provider-opennebula = ./nix/provider-opennebula.nix;
        default = self.nixosModules.services;
      };

      lib = {
        # The seam a deployment tool builds on, so that it keeps no copy of what
        # these modules decide: address helpers, the port tables and the
        # comparison of a Leandro patch series with ours. The renderer of
        # MEISTER_* context defaults is not on it: a deployment tool gets it
        # through nixosModules.store-host.
        net = import ./nix/lib/net.nix { inherit lib; };
        ports = (import ./nix/lib/ports.nix).roles;
        addonPorts = (import ./nix/lib/ports.nix).addons;
        leandroSeries = import ./nix/lib/leandro-series.nix { inherit lib; };
        patchDir = ./patches;
      };

      # Expose package overrides through an overlay.
      overlays.default = import ./nix/overlay.nix;

      packages.${system} = {
        # Workspace and runtime packages.
        inherit (pkgs)
          meisterstack
          meisterstack-static
          meisterstack-runtime
          cloud-hypervisor-meister
          cloud-hypervisor-meister-static
          vhost-device-input
          guest-tiny
          # Operator-side CA utility.
          meister-ca
          ;

        module-options =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              # Generate option documentation for all exported modules.
              modules = [
                self.nixosModules.services
                self.nixosModules.store-host
                self.nixosModules.provider-opennebula
              ] ++ [{
                nixpkgs.hostPlatform = system;
                nixpkgs.overlays = [ self.overlays.default ];
                fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
                boot.loader.grub.device = "nodev";
              }];
            };
            doc = pkgs.nixosOptionsDoc {
              options = { inherit (evaluated.options) meisterstack; };
              # Normalize declaration source paths in generated option documentation.
              transformOptions = opt: builtins.removeAttrs opt [ "declarations" ];
              warningsAreErrors = false;
            };
          in
          doc.optionsJSON;
      };

      # Provide musl C compilation and linking inputs for a separately installed Rust
      # toolchain. Keep this shell focused on the target libraries used by the workspace.
      devShells.${system} =
        let
          cc = pkgs.pkgsCross.musl64.stdenv.cc;
          musl = pkgs.mkShell {
            packages = [ cc ];
            env = {
              CC_x86_64_unknown_linux_musl = "${cc}/bin/x86_64-unknown-linux-musl-gcc";
              AR_x86_64_unknown_linux_musl = "${cc}/bin/x86_64-unknown-linux-musl-ar";
              CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER =
                "${cc}/bin/x86_64-unknown-linux-musl-gcc";
            };
            shellHook = ''
              echo "musl cross toolchain on PATH — cargo build --release --target x86_64-unknown-linux-musl"
            '';
          };
        in
        {
          inherit musl;
          # Use the same shell for the default nix develop invocation.
          default = musl;
        };
      checks.${system} = {
        # nix/services.nix decides nothing about the machine.
        services-are-pure = import ./nix/tests/services-are-pure.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # A host of the service modules alone gets defaults that fail closed.
        standalone-host = import ./nix/tests/standalone-host.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # The agent unit's sandbox keeps what the agent's work depends on.
        agent-unit-sandbox = import ./nix/tests/agent-unit-sandbox.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # A tenant router outlives the agent that built it (IKR-B69).
        vm-router-netns-outlives-agent = import ./nix/tests/router-netns-outlives-agent.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Every host binds its metrics where its Prometheus scrapes them.
        scrape-targets = import ./nix/tests/scrape-targets.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Check resolver ownership with optional provider initialization.
        one-resolver-author = import ./nix/tests/one-resolver-author.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Check store-built provider initialization without configuration rendering.
        provider-opennebula-reads-its-context =
          import ./nix/tests/provider-opennebula-reads-its-context.nix {
            inherit nixpkgs lib pkgs system self;
          };

        # A store-built host's units start the runtime package of its own
        # generation and wait for keys, never for a binary.
        store-host-uses-the-package = import ./nix/tests/store-host-uses-the-package.nix {
          inherit lib pkgs;
          host = storeHostOf "probe" [ "cloud" "cluster" "agent" ];
        };

        # The roles reach the legacy boot renderer as MEISTER_ROLE in context.env.
        roles-context-env = import ./nix/tests/roles-context-env.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # The binaries accept every config file these modules render.
        services-check-config = import ./nix/tests/services-check-config.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Check that disabling NVMe/TCP removes its advertised backends.
        no-fabric-no-claim = import ./nix/tests/no-fabric-no-claim.nix {
          inherit nixpkgs lib pkgs system self;
        };


        raft-member-starts-alone = import ./nix/tests/raft-member-starts-alone.nix {
          inherit nixpkgs lib pkgs system self;
        };
        # Validate installer output in a scratch root.
        install-script = import ./nix/tests/install-script.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Keep guests from opening connections to their host.
        vm-guest-guard = import ./nix/tests/guest-guard.nix {
          inherit nixpkgs lib pkgs system self;
        };
        # The same beside a NixOS nftables firewall that flushes the ruleset.
        vm-guest-guard-nftables = import ./nix/tests/guest-guard.nix {
          inherit nixpkgs lib pkgs system self;
          hostRunsNftables = true;
        };

        # A control plane and an agent from the service modules alone, and a
        # guest created through the cloud API that boots on the agent.
        vm-two-node-services = import ./nix/tests/two-node-services.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Exercise standalone socket access and a nested guest.
        vm-single-node = import ./nix/tests/single-node.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Check runtime private-key permissions.
        vm-credentials = import ./nix/tests/credentials.nix {
          inherit nixpkgs lib pkgs system self;
        };

        # Compare a Leandro patch series with ours, both ways.
        leandro-series = import ./nix/tests/leandro-series.nix {
          inherit lib pkgs;
        };
        # Check that built runtime artifacts contain no developer-specific paths.
        no-developer-home = import ./nix/tests/no-developer-home.nix {
          inherit lib pkgs;
          configs = storeHosts;
        };
      };
    };
}
