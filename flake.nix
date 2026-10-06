# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

{
  description = "MeisterStack: the modules, the packages and lib.mkFleet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    # Disk-layout input shared with operator flakes.
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Optional generator for image formats not using the native builder.
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, disko, nixos-generators }:
    let
      system = "x86_64-linux";
      # Instantiate the package set with the repository overlay.
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
      lib = nixpkgs.lib;

      inventoryLib = import ./nix/lib/inventory.nix { inherit lib; };

      # Evaluate example fleets for outputs and checks; real deployments use an operator repository.
      mkFleet = import ./nix/lib/mkFleet.nix;
      fleetOf = inventory: profiles: mkFleet
        {
          inherit nixpkgs disko nixos-generators;
          meisterstack = self;
        }
        { inherit inventory profiles; inherit system; };

      exampleProfiles = import ./examples/fleet/profiles.nix { inherit lib; };
      example = fleetOf ./examples/fleet/one-box.toml exampleProfiles;
      exampleHa = fleetOf ./examples/fleet/ha.toml exampleProfiles;
      # Standalone example with the agent and local CLI.
      exampleSingle = fleetOf ./examples/fleet/single-node.toml exampleProfiles;

    in
    {
      # Public module composition: services define runtime integration; managed adds
      # closure-based deployment. Host profiles retain machine policy.
      nixosModules = {
        services = ./nix/services.nix;
        managed = ./nix/managed.nix;
        # Optional OpenNebula provider initialization, separate from the default module.
        provider-opennebula = ./nix/provider-opennebula.nix;
        default = self.nixosModules.services;
      };

      # Export the fleet constructor with this flake's inputs.
      lib = {
        inherit mkFleet;
        # Expose inventory parsing independently of system evaluation.
        inventory = inventoryLib;
      };

      # Expose package overrides through an overlay.
      overlays.default = import ./nix/overlay.nix;

      # Operator repository template.
      templates.operator = {
        path = ./templates/operator;
        description = "A MeisterStack deployment: fleet.toml, profiles, hosts and the checks";
      };

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
                self.nixosModules.managed
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
        # Reuse the example fleet's packages and checks.
        example-manifest = example.packages.${system}.manifest;
        example-installer = example.packages.${system}.box-installer;
        example-disk-image = example.packages.${system}.box-disk-image;
        example-managed-disk-image = example.packages.${system}.managed-disk-image;
        # Expose the example direct-boot provider bundle.
        example-direct-boot = example.packages.${system}.n2-direct-boot;

      };

      # Expose example systems for evaluation and build checks.
      nixosConfigurations = example.nixosConfigurations;

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
      checks.${system} =
        # Reuse fleet configuration, inventory, and manifest checks.
        example.checks.${system}
        // lib.mapAttrs' (n: lib.nameValuePair "ha-${n}") exampleHa.checks.${system}
        // lib.mapAttrs' (n: lib.nameValuePair "single-${n}") exampleSingle.checks.${system}
        // {
          # nix/services.nix decides nothing about the machine.
          services-are-pure = import ./nix/tests/services-are-pure.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # A host without nix/managed.nix gets defaults that fail closed.
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

          # Every host binds its metrics where the fleet's Prometheus scrapes them.
          scrape-targets = import ./nix/tests/scrape-targets.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # A managed host's units name the store, never /opt.
          managed-uses-the-package = import ./nix/tests/managed-uses-the-package.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Check resolver ownership with optional provider initialization.
          one-resolver-author = import ./nix/tests/one-resolver-author.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Check managed provider initialization without configuration rendering.
          managed-may-read-its-provider =
            import ./nix/tests/managed-may-read-its-provider.nix {
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

          # Exercise standalone socket access and a nested guest.
          vm-single-node = import ./nix/tests/single-node.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Exercise activation, confirmation, and timer-based recovery.
          vm-activate-semantics = import ./nix/tests/activate.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Exercise signed closure transport, update, rollback, and resume.
          vm-managed-update = import ./nix/tests/update.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Check runtime private-key permissions.
          vm-credentials = import ./nix/tests/credentials.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Exercise enrollment, certificate delivery, and reconnecting sessions.
          vm-keys-roundtrip = import ./nix/tests/keys.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Exercise certificate revocation and interrupted key rotation.
          vm-keys-revoke = import ./nix/tests/keys-revoke.nix {
            inherit nixpkgs lib pkgs system self;
          };
          # Exercise installation and UEFI boot fallback.
          vm-install-blank-disk = import ./nix/tests/install.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # Exercise provider-loaded direct boot.
          vm-install-direct-boot = import ./nix/tests/install-direct.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # Exercise installation, enrollment, bootstrap, update, and provider reboot.
          vm-bootstrap-fleet = import ./nix/tests/bootstrap.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # Check that copies of a generic image acquire distinct identities.
          vm-two-instances-same-image = import ./nix/tests/two-instances.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # Exercise degraded-quorum rollout checks.
          vm-quorum-degraded = import ./nix/tests/quorum.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # Exercise approval and execution of a kernel-parameter reboot.
          vm-kernel-change = import ./nix/tests/kernel.nix {
            inherit nixpkgs lib pkgs system self;
          };
          # Check tiny-guest boot behavior with the patched hypervisor.
          installer-no-secrets =
            let
              host = example.nixosConfigurations.box.config;
              embedded = [
                host.system.build.toplevel
                host.system.build.diskoScript
              ];
              closure = pkgs.closureInfo { rootPaths = embedded; };
            in
            pkgs.runCommand "installer-no-secrets" { } ''
              echo "== the closure the example installer embeds"
              wc -l < ${closure}/store-paths

              # A store path whose NAME ends in .key or .sec, or that calls
              # itself secrets. None of this stack's key material is ever in
              # the store — it is written to the target by `keys deliver`
              # (M3B) — so a path like that is either somebody's accident or
              # a dependency that carries an example key, and both are
              # things to look at before an image travels.
              if grep -E '\.(key|sec)$|secrets$' ${closure}/store-paths > bad-names; then
                echo "the medium would carry key material:"
                cat bad-names
                exit 1
              fi

              # And the one place a private key would actually be read from:
              # the /etc this system ships. `-R` and not `-r`, because a
              # NixOS /etc is a tree of symlinks into the store and `-r`
              # would walk past all of it.
              # `-s` as well: a NixOS /etc has dangling symlinks in it (a
              # font configuration that points at a version directory which
              # is not there), and a check that printed a warning about one
              # would be a check somebody learns to ignore.
              if grep -RIls 'PRIVATE KEY' ${host.system.build.toplevel}/etc > bad-files; then
                echo "the medium would carry a private key in /etc:"
                cat bad-files
                exit 1
              fi

              echo "  ok   no key material in the closure and none in /etc"
              touch $out
            '';

          # Check the optional GPU profile with a stub package input.
          gpu-profile = import ./nix/tests/gpu-profile.nix {
            inherit nixpkgs lib pkgs system self;
          };
          # Refuse a leandro input whose cloud-hypervisor patch series is not ours.
          leandro-series = import ./nix/tests/leandro-series.nix {
            inherit lib pkgs;
            fleetWith = leandro: mkFleet
              {
                inherit nixpkgs disko nixos-generators leandro;
                meisterstack = self;
              }
              { inventory = ./examples/fleet/one-box.toml; profiles = exampleProfiles; inherit system; };
          };
          # Validate malformed inventory fixtures.
          inventory-conflicts = import ./nix/tests/inventory-conflicts.nix {
            inherit lib pkgs inventoryLib;
          };

          # Check that built runtime artifacts contain no developer-specific paths.
          no-developer-home = import ./nix/tests/no-developer-home.nix {
            inherit lib pkgs;
            configs = lib.mapAttrs (_: s: s.config) example.nixosConfigurations;
          };

          # Check the direct-boot bundle's kernel, initrd, and command line.
          example-direct-boot = pkgs.runCommand "direct-boot-is-three-files" { } ''
            bundle=${example.packages.${system}.n2-direct-boot}
            test -e "$bundle/kernel" || { echo "no kernel in the bundle"; exit 1; }
            test -e "$bundle/initrd" || { echo "no initrd in the bundle"; exit 1; }
            grep -q ' init=/nix/store/.*-nixos-system-n2-.*/init$' "$bundle/cmdline"               || { echo "the command line does not name n2's init:"; cat "$bundle/cmdline"; exit 1; }
            # And the two names point INTO the store rather than at a copy:
            # many hosts share one kernel, and a copy per host would be a
            # gigabyte per host for no fact anybody gains.
            case "$(readlink -f "$bundle/kernel")" in
              /nix/store/*) ;;
              *) echo "the kernel is not a store path"; exit 1 ;;
            esac
            touch $out
          '';

          # Build a minimal CPU host.
          example-cpu-host = example.nixosConfigurations.n1.config.system.build.toplevel;

          # Check the evaluated standalone profile.
          example-single-node =
            let host = exampleSingle.nixosConfigurations.rig.config; in
            pkgs.runCommand "example-single-node" { } ''
              agent=${host.environment.etc."meisterstack/agent.toml".source}
              cli=${host.environment.etc."meisterstack/cli.toml".source}
              grep -q '^node_id = "rig"' "$agent"
              if grep -q 'controller_' "$agent"; then
                echo "the single node's agent names a controller, or a session credential:"; cat "$agent"; exit 1
              fi
              grep -q 'socket_group = "meister"' "$agent"
              grep -q 'default_profile = "local"' "$cli"
              grep -q 'endpoint = "unix:///run/meisterstack/agent/agent.sock"' "$cli"
              touch $out
            '';

          # Build the example control plane and carrier hosts.
          example-topology = pkgs.runCommand "example-topology" { } ''
            ${lib.concatMapStrings
              (id: ''
                echo "== ${id}: ${lib.concatStringsSep "," example.inventory.hosts.${id}.roles}"
                test -e ${example.nixosConfigurations.${id}.config.system.build.toplevel}/init
              '')
              (lib.attrNames example.nixosConfigurations)}
            touch $out
          '';

          # Evaluate the multi-member HA topology.
          example-topology-ha = pkgs.runCommand "example-topology-ha" { } ''
            ${lib.concatMapStrings
              (id: ''
                echo "== ${id}: ${lib.concatStringsSep "," exampleHa.inventory.hosts.${id}.roles}"
                test -e ${exampleHa.nixosConfigurations.${id}.config.system.build.toplevel}/init
              '')
              (lib.attrNames exampleHa.nixosConfigurations)}
            touch $out
          '';

          # Evaluate an external flake importing the public module interface.
          foreign-flake =
            let
              foreign = (import ./examples/fleet/foreign-flake/flake.nix).outputs {
                self = null;
                inherit nixpkgs;
                meisterstack = self;
              };
              cfg = foreign.nixosConfigurations.box.config;
            in
            pkgs.runCommand "foreign-flake-imports-us" { } ''
              grep -qx 'MEISTER_ROLE=agent,cluster,cloud' \
                ${cfg.environment.etc."meisterstack/context.env".source}
              grep -q metrics_listen ${cfg.environment.etc."meisterstack/cloud.toml".source}

              # And the two the host decides and we must not. The example
              # sets 24.11 and a firewall ON; a module of ours sets neither,
              # and `services-are-pure` is the check that says so. If either
              # of these lines ever reads like an answer of ours, a module
              # has started deciding something that belongs to somebody
              # else's machine.
              test '${cfg.system.stateVersion}' = '24.11' \
                || { echo "the foreign host's stateVersion is ${cfg.system.stateVersion}, not its own 24.11"; exit 1; }
              ${lib.optionalString (!cfg.networking.firewall.enable)
                "echo 'the foreign host asked for a firewall and did not get one'; exit 1"}
              touch $out
            '';
        };
    };
}
