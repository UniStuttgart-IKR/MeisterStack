# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

{
  description = "MeisterStack: the modules, the packages and lib.mkFleet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    # Disk layouts for the first install (M3). Declared here so that an
    # operator's `disko.follows = "meisterstack/disko"` has something to
    # follow and the lock file does not change when M3 starts using it.
    # Revision from M0 probe S6, which evaluated it against this nixpkgs.
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The pre-v1 image generator. Still an input because only ONE format has
    # been measured against the native `system.build.images` so far — the
    # installer, in M0 probe S4, byte-for-byte equal — and a format that has
    # not been measured is not a format to swap silently. `lib.mkFleet` takes
    # `images.<format> = "nixos-generators"` for those.
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, disko, nixos-generators }:
    let
      system = "x86_64-linux";
      # With this repository's own packages in it (nix/overlay.nix): the
      # modules reach them through `pkgs.meisterstack`, so the flake that
      # declares them has to be evaluating a nixpkgs that has them.
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
      lib = nixpkgs.lib;

      inventoryLib = import ./nix/lib/inventory.nix { inherit lib; };

      # THE EXAMPLE FLEET, and it is only that.
      #
      # This repository builds no fleet out of its own root any more. The
      # pre-v1 flake looked for `./fleet.toml` and fell back to
      # examples/fleet/one-box.toml, which made every `nix build` in a
      # checkout a build of a fleet that nobody had declared — and hid the
      # question of WHOSE repository a deployment lives in. A deployment is
      # the operator's own repository now (`meister-deploy init`), and what
      # is left here is a worked example that `nix flake check` checks.
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

      # The role-agnostic image for OpenNebula: every unit ships, and the
      # CONTEXT decides at boot which of them starts. `appliance` and not
      # `default`, because `default` is the SERVICES and they decide nothing
      # about the machine — no stateVersion, no firewall, no console, and no
      # units at all without a role.
      applianceModules = [ self.nixosModules.appliance ];
    in
    {
      # What a host that is not ours imports.
      #
      #   imports = [ meisterstack.nixosModules.default ];
      #   meisterstack.roles = [ "cloud" "cluster" ];
      #   meisterstack.cloud.settings = { ... };
      #
      # `default` is `services`: the units, their config files, their users
      # and their state — and NOTHING about the machine. No stateVersion, no
      # firewall, no dhcp, no bootloader, no `fileSystems."/"`, no console.
      # Somebody else's NixOS host has answers to all of those already, and
      # `checks.services-are-pure` holds this export to it.
      #
      # Beside it are the three PROFILES, which are allowed to decide such
      # things because each of them is a whole machine:
      #
      #   appliance  today's image: the services, the boot renderer, the
      #              OpenNebula provider, and base.nix' host-global set.
      #   managed    a host meister-deploy deploys to: nix on, config files
      #              complete at build time, no renderer. `lib.mkFleet` gives
      #              it to every host the inventory calls `nixos`.
      #   context    the boot renderer on its own, for a host that wants one
      #              without the rest of the appliance.
      nixosModules = {
        services = ./nix/services.nix;
        managed = ./nix/managed.nix;
        appliance = ./nix/appliance.nix;
        context = ./nix/context.nix;
        provider-opennebula = ./nix/provider-opennebula.nix;
        default = self.nixosModules.services;
      };

      # The whole of what an operator's flake calls; nix/lib/mkFleet.nix has
      # the signature and the rationale.
      #
      #   outputs = { nixpkgs, meisterstack, disko, ... }:
      #     meisterstack.lib.mkFleet { inherit nixpkgs disko meisterstack; } {
      #       inventory = ./fleet.toml;
      #       profiles = import ./profiles.nix { inherit (nixpkgs) lib; };
      #     };
      lib = {
        inherit mkFleet;
        # The inventory reader on its own, for a tool that wants to look at a
        # `fleet.toml` without building anything.
        inventory = inventoryLib;
      };

      # What this repository builds, for a nixpkgs that is not ours.
      #
      #   nixpkgs.overlays = [ meisterstack.overlays.default ];
      #   environment.systemPackages = [ pkgs.meisterstack ];
      overlays.default = import ./nix/overlay.nix;

      # The repository a deployment starts from:
      #
      #   nix flake new -t github:UniStuttgart-IKR/MeisterStack my-fleet
      #   meister-deploy init my-fleet          # the same files, plus the lock
      #
      # templates/operator/ is what `meister-deploy init` writes, file for
      # file — one copy, two roads to it, and a test in the crate compares
      # the embedded list with the directory.
      templates.operator = {
        path = ./templates/operator;
        description = "A MeisterStack deployment: fleet.toml, profiles, hosts and the checks";
      };

      packages.${system} = {
        # The binaries, out of Nix rather than out of somebody's
        # target/release. nix/packages/*.nix carries the rationale for each.
        inherit (pkgs)
          meisterstack
          meisterstack-static
          meisterstack-runtime
          cloud-hypervisor-meister
          vhost-device-input
          guest-tiny
          ;

        module-options =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              # The appliance plus `managed`: the table documents every
              # option this flake exports, and the two profiles are mutually
              # exclusive only in their `enable`, not in their declarations.
              # Without this line the managed half of the stack would have no
              # documentation at all.
              modules = applianceModules ++ [ self.nixosModules.managed ] ++ [{
                nixpkgs.hostPlatform = system;
                nixpkgs.overlays = [ self.overlays.default ];
                fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
                boot.loader.grub.device = "nodev";
              }];
            };
            doc = pkgs.nixosOptionsDoc {
              options = { inherit (evaluated.options) meisterstack; };
              # The file a declaration lives in is a store path here and a
              # repository path to a reader; neither is what the table shows,
              # so it is dropped rather than rendered wrong.
              transformOptions = opt: builtins.removeAttrs opt [ "declarations" ];
              warningsAreErrors = false;
            };
          in
          doc.optionsJSON;
        # The example fleet's own outputs, so that what `nix flake check`
        # checks can also be looked at by hand:
        #
        #   nix build .#example-manifest && jq . result
        #   nix build .#example-installer   # the native iso-installer (M3)
        example-manifest = example.packages.${system}.manifest;
        example-installer = example.packages.${system}.box-installer;
        example-disk-image = example.packages.${system}.box-disk-image;
        example-managed-disk-image = example.packages.${system}.managed-disk-image;
        # The other boot mode: what a provider is handed for the example
        # fleet's one `boot = "direct"` host — a kernel, an initrd and the
        # command line that names the system they belong to.
        #
        #   nix build .#example-direct-boot && cat result/cmdline
        example-direct-boot = example.packages.${system}.n2-direct-boot;

        # The generic appliance image, unchanged: the twelve context VMs of
        # the lab boot this, and they will until their migration is done
        # (L3). It is the one image that is NOT a fleet host — no hostname,
        # no roles, no addresses — because the context decides all of that
        # at boot.
        control-plane-image = nixos-generators.nixosGenerate {
          inherit system;
          modules = applianceModules;
          format = "qcow";
        };

        # The same image from the native builder, for the parity measurement
        # the brief of this lane asks for (M0 probe S4 did it for the
        # installer; these two are qemu/qcow and raw-efi). Both are built and
        # compared in the report; until they are equal for a format, that
        # format keeps its nixos-generators road.
        control-plane-image-native =
          (nixpkgs.lib.nixosSystem {
            modules = applianceModules ++ [{
              nixpkgs.hostPlatform = system;
              nixpkgs.overlays = [ self.overlays.default ];
            }];
          }).config.system.build.images.qemu;
      };

      # One system per host of the EXAMPLE fleet, so that `nix flake check`
      # evaluates them — which is also what makes every assertion of every
      # host fire here rather than in a deployment.
      nixosConfigurations = example.nixosConfigurations // {
        # The appliance as a plain NixOS system: how the rendered role
        # templates can be read without booting anything.
        #
        #   nix build --no-link --print-out-paths \
        #     '.#nixosConfigurations.control-plane.config.environment.etc."meisterstack/cloud.toml".source'
        control-plane = nixpkgs.lib.nixosSystem {
          modules = applianceModules ++ [{
            nixpkgs.hostPlatform = system;
            nixpkgs.overlays = [ self.overlays.default ];
            # Only so that this configuration evaluates to the END: a system
            # without a root filesystem is an assertion rather than a value.
            # The two lines are what the qcow format sets anyway.
            fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
            boot.loader.grub.device = "nodev";
          }];
        };
      };

      # The one shell this repository needs, and it exists because a musl
      # build needed hand-typed store paths without it.
      #
      # `ring` (under rustls, under every session in this stack) compiles C for
      # the target, so a static musl binary needs a musl cross-gcc — and `cc`
      # looks for it under a name plain cargo cannot supply on a host whose
      # toolchain is glibc. Without a shell the only way was `nix shell
      # nixpkgs#pkgsCross.musl64.stdenv.cc` plus three exports typed by hand
      # against store paths that a `nix gc` moves, which is what
      # `meister-deploy push` and deploy/push.sh ran into in the lab on
      # 2026-09-10.
      #
      # Three variables and no more. They are the three `cc` and cargo read,
      # spelled with the target in them, so the shell changes NOTHING about a
      # native build done in it — `cargo build` for the host is the same build
      # inside this shell as outside it.
      #
      # No rust toolchain: the one on the developer's machine is the one this
      # repository is built with everywhere else (rustup, the pinned
      # toolchain), and a second one out of nixpkgs would be a second answer to
      # "which compiler built this" that nobody asked for. What the shell adds
      # is the C half, which nobody has.
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
          # The same shell under the name a bare `nix develop` takes: there is
          # only one thing to be in this repository, and a `default` that was
          # something else would make `nix develop` the wrong half of it.
          default = musl;
        };
      checks.${system} =
        # The checks lib.mkFleet gives every fleet: the real parsers against
        # the rendered configuration files (`config-<id>`), the two readers of
        # the inventory against each other (`inventory-parity`), and what Nix
        # derived against the types that read it (`manifest-json`).
        example.checks.${system}
        // lib.mapAttrs' (n: lib.nameValuePair "ha-${n}") exampleHa.checks.${system}
        // {
          # nix/services.nix decides nothing about the machine.
          services-are-pure = import ./nix/tests/services-are-pure.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # A managed host's units name the store, never /opt.
          managed-uses-the-package = import ./nix/tests/managed-uses-the-package.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # What the target-side helper does to a REAL machine: the profile
          # moves, the timer fires, and a host nobody confirms comes back by
          # itself (M2C).
          vm-activate-semantics = import ./nix/tests/activate.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # The exit criterion of M2: an operator workstation changes a
          # managed host over ssh and brings it back, with a receipt for
          # both (M2C).
          vm-managed-update = import ./nix/tests/update.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # What a private key on a managed host looks like, and what the
          # loader says when it does not (M0 probe S11, M2C).
          vm-credentials = import ./nix/tests/credentials.nix {
            inherit nixpkgs lib pkgs system self;
          };

          # An empty virtual disk becomes a host that boots itself, and a
          # second medium refuses to do it again (M3A: V06 part 1, V07 —
          # and the boot-mode rollback on a real ESP, which 2C could not
          # measure on a machine started with `-kernel`).
          vm-install-blank-disk = import ./nix/tests/install.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # The other boot mode: a guest with no boot loader at all, started
          # by the test driver out of the bundle its provider would be
          # handed (M3A position 8).
          vm-install-direct-boot = import ./nix/tests/install-direct.nix {
            inherit nixpkgs lib pkgs system self disko;
          };

          # The boot renderer and the build-time renderer, on the same input.
          # Both fleets: one-box has a raft group of ONE (no etcd variables),
          # ha has three (1A §8, open point 6).
          render-parity = import ./nix/tests/render-parity.nix {
            inherit nixpkgs lib pkgs system self disko;
            inv = example.inventory;
            hostIds = [ "box" "n1" ];
            profiles = exampleProfiles;
          };
          render-parity-ha = import ./nix/tests/render-parity.nix {
            inherit nixpkgs lib pkgs system self disko;
            inv = exampleHa.inventory;
            hostIds = [ "cp-a" "cp-b" "a1" ];
            profiles = exampleProfiles;
          };

          # An inventory that cannot be deployed cannot be built.
          inventory-conflicts = import ./nix/tests/inventory-conflicts.nix {
            inherit lib pkgs inventoryLib;
          };

          # Nothing in this fleet comes out of a developer's home (V04/L01).
          no-developer-home = import ./nix/tests/no-developer-home.nix {
            inherit lib pkgs;
            configs = lib.mapAttrs (_: s: s.config) example.nixosConfigurations;
          };

          # The bundle of the one direct-boot host, built: three names in a
          # directory, and the command line names the toplevel whose `init`
          # the kernel is to start. Cheap — the kernel and the initrd are the
          # ones `example-topology` builds anyway — and it is what keeps the
          # second boot mode a thing that EXISTS rather than a field in a
          # contract.
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

          # One CPU host, built. The smallest thing that proves a fleet host
          # is a real system: an agent with no controller of its own, whose
          # addresses come from the group its inventory entry names.
          example-cpu-host = example.nixosConfigurations.n1.config.system.build.toplevel;

          # And a whole small topology: the control plane and both carriers.
          example-topology = pkgs.runCommand "example-topology" { } ''
            ${lib.concatMapStrings
              (id: ''
                echo "== ${id}: ${lib.concatStringsSep "," example.inventory.hosts.${id}.roles}"
                test -e ${example.nixosConfigurations.${id}.config.system.build.toplevel}/init
              '')
              (lib.attrNames example.nixosConfigurations)}
            touch $out
          '';

          # The other shape of the same fleet: a raft group of three and two
          # agents, so that the etcd road is built and not only evaluated.
          example-topology-ha = pkgs.runCommand "example-topology-ha" { } ''
            ${lib.concatMapStrings
              (id: ''
                echo "== ${id}: ${lib.concatStringsSep "," exampleHa.inventory.hosts.${id}.roles}"
                test -e ${exampleHa.nixosConfigurations.${id}.config.system.build.toplevel}/init
              '')
              (lib.attrNames exampleHa.nixosConfigurations)}
            touch $out
          '';

          # A flake that is not ours, importing what we export: its own
          # stateVersion, its own firewall, its own hardware — and one host
          # of a fleet all the same (V03). It is EVALUATED rather than
          # locked: its `outputs` is called with this flake in the place of
          # its own `meisterstack` input, which is what a real `nix build` in
          # that directory would pass it.
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
              # sets 24.11 and a firewall ON; ours would be 25.11 and a
              # firewall off (nix/appliance.nix). If either of these lines
              # ever reads like our answer, a module of ours has started
              # deciding something that belongs to somebody else's machine.
              test '${cfg.system.stateVersion}' = '24.11' \
                || { echo "the foreign host's stateVersion is ${cfg.system.stateVersion}, not its own 24.11"; exit 1; }
              ${lib.optionalString (!cfg.networking.firewall.enable)
                "echo 'the foreign host asked for a firewall and did not get one'; exit 1"}
              touch $out
            '';
        };
    };
}
