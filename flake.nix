# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

{
  description = "MeisterStack: the modules, one image per planned node, and the generic one";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, nixos-generators }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;

      fleetLib = import ./nix/fleet.nix { inherit lib; };

      # The plan this flake builds outputs for. A deployment writes its own
      # `fleet.toml` next to this file and `git add`s it — a flake does not
      # see untracked files — and everything below is then that fleet's.
      # Without one, the worked example IS the plan, so `nix flake check` has
      # something real to check and the recipe in config/examples/one-box can
      # be typed as it stands.
      planFile =
        if builtins.pathExists ./fleet.toml
        then ./fleet.toml
        else ./examples/fleet/one-box.toml;
      plan = fleetLib.load planFile;

      # The role-agnostic image for OpenNebula: every unit ships, and the
      # CONTEXT decides at boot which of them starts.
      genericModules = [ self.nixosModules.default ];

      # Everything a planned node is: our modules, what the plan says about
      # this node, and the operator's own files. One list, used by the images
      # and by `nixosConfigurations` alike, so that `nix build .#image-<node>`
      # and `nixos-rebuild switch --flake .#<node>` are the same system.
      nodeModules = node: genericModules ++ [
        { nixpkgs.hostPlatform = system; }
        (plan.nodeModule node)
      ] ++ node.modules;
    in
    {
      # What a host that is not ours imports. `default` is the whole stack
      # with nothing selected — `meisterstack.roles` decides what runs — and
      # the single modules are there for a configuration that wants to compose
      # by hand:
      #
      #   imports = [ meisterstack.nixosModules.default ];
      #   meisterstack.roles = [ "cloud" "cluster" ];
      #   meisterstack.cloud.settings = { ... };
      #
      # `nixosConfigurations` below builds every planned node out of exactly
      # these, so there is one road into this stack rather than a second one
      # to keep in step with the first.
      nixosModules = {
        roles = ./nix/roles.nix;
        base = ./nix/base.nix;
        one-context = ./nix/one-context.nix;
        etcd = ./nix/etcd.nix;
        controllers = ./nix/controllers.nix;
        agent = ./nix/agent.nix;
        addons = ./nix/addons.nix;
        data = ./nix/data.nix;
        observability = ./nix/observability.nix;
        default = {
          imports = [
            self.nixosModules.roles
            self.nixosModules.base
            self.nixosModules.one-context
            self.nixosModules.etcd
            self.nixosModules.controllers
            self.nixosModules.agent
            self.nixosModules.addons
            self.nixosModules.data
            self.nixosModules.observability
          ];
        };
      };

      # One image per PLANNED node, and the generic one beside them.
      #
      #   nix build .#control-plane-image   qcow2, role-agnostic, OpenNebula
      #   nix build .#image-<node>          raw-efi, `dd` it onto that box
      #   nix build .#iso-<node>            the same system as an installer
      #
      # The per-node images bake the hostname, the roles, the derived
      # addresses and the operator's own modules — and NO KEYS. A private key
      # must never travel in an image: an image gets copied, shared and stored
      # in a datastore, and `meister-deploy keys push` is the road that exists
      # instead. The units of every role therefore come up visibly skipped on
      # a freshly written disk, which is the honest state and a sentence
      # `systemctl status` can say.
      #
      # nixos-anywhere is the alternative to `dd` for a box that is already
      # running something else and is reachable over ssh: it kexecs a NixOS
      # installer, partitions with disko and installs
      # `.#nixosConfigurations.<node>` — the SAME system these images hold, so
      # nothing about the plan changes. It needs a disko layout the plan does
      # not carry today, which is why it is a paragraph in deploy/README.md
      # rather than an output here.
      packages.${system} = {
        # The options a foreign host sees. A configuration that imports
        # `nixosModules.default` gets option NAMES and nothing else — no brief,
        # no worked example — so the module's own descriptions are the
        # documentation, and this output is how they leave the module without
        # being retyped anywhere. scripts/module-options.sh turns it into the
        # table in deploy/README.md and checks that the table is still current.
        module-options =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              modules = genericModules ++ [{
                nixpkgs.hostPlatform = system;
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

        control-plane-image = nixos-generators.nixosGenerate {
          inherit system;
          modules = genericModules;
          format = "qcow";
        };
      } // lib.listToAttrs (lib.concatMap
        (node: [
          (lib.nameValuePair "image-${node.name}" (nixos-generators.nixosGenerate {
            inherit system;
            modules = nodeModules node;
            format = "raw-efi";
          }))
          # The installer variant, because nixos-generators gives it for the
          # price of one word: same system, same plan, but booted from a stick
          # for a box whose disk is not reachable from here.
          (lib.nameValuePair "iso-${node.name}" (nixos-generators.nixosGenerate {
            inherit system;
            modules = nodeModules node;
            format = "install-iso";
          }))
        ])
        plan.metalNodes);

      # The same modules as a plain NixOS system. Nothing is deployed from
      # here — the image above is what ships, and `nix.enable = false` in
      # base.nix means a booted VM is never rebuilt — but it is how the
      # rendered role templates can be read without booting anything:
      #
      #   nix build --no-link --print-out-paths \
      #     '.#nixosConfigurations.control-plane.config.environment.etc."meisterstack/cloud.toml".source'
      #
      # which is the check that the config keys this image bakes are the keys
      # the binaries take. The qcow format module is left out on purpose: it
      # brings a bootloader and a root filesystem this evaluation does not
      # need, and every attribute read this way is a pure config value.
      #
      # Next to it, one system per METAL node of the plan: hostname, roles,
      # addresses and settings baked, and `meister-deploy push` hands exactly
      # these to `nixos-rebuild switch --target-host`.
      nixosConfigurations = {
        control-plane = nixpkgs.lib.nixosSystem {
          modules = genericModules ++ [{
            nixpkgs.hostPlatform = system;
            # Only so that this configuration evaluates to the END: `nix flake
            # check` builds every nixosConfiguration's toplevel, and a system
            # without a root filesystem is an assertion rather than a value.
            # The two lines are what the qcow format above sets anyway, so
            # this is not a second answer to the same question.
            fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
            boot.loader.grub.device = "nodev";
          }];
        };
      } // lib.listToAttrs (map
        (node: lib.nameValuePair node.name (nixpkgs.lib.nixosSystem {
          modules = nodeModules node;
        }))
        plan.metalNodes);

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

      checks.${system} = {
        # The plan itself. Every rule in nix/fleet.nix throws at evaluation,
        # so a plan that cannot be deployed cannot be built either; forcing
        # the rendered files of every planned node is what makes that throw
        # happen HERE rather than at somebody's first `nix build`.
        fleet-plan = pkgs.runCommand "fleet-plan-checks" { } (
          lib.concatMapStrings
            (node:
              let cfg = self.nixosConfigurations.${node.name}.config; in ''
                echo "== ${node.name}: ${lib.concatStringsSep "," node.roles} @ ${node.address}"
                grep -q '^MEISTER_ROLE=' \
                  ${cfg.environment.etc."meisterstack/context.env".source}
                test -s ${cfg.environment.etc."meisterstack/cloud.toml".source}
                test -s ${cfg.environment.etc."meisterstack/agent.toml".source}
              '')
            plan.metalNodes
          + "touch $out\n"
        );

        # A flake that is not ours, importing what we export — and, next to
        # it, one node of the example plan as `meister-deploy render` wrote
        # it. That is the third road into these modules: no image, no
        # meister-deploy at build time, just a host with its own
        # configuration that also happens to be a node of this fleet.
        #
        # It is EVALUATED
        # rather than locked: its `outputs` is called with this flake in the
        # place of its own `meisterstack` input, which is what a real `nix
        # build` in that directory would pass it. So the check needs no
        # network, and it still fails the moment `nixosModules.default` stops
        # standing on its own.
        foreign-flake =
          let
            foreign = (import ./examples/fleet/foreign-flake/flake.nix).outputs {
              self = null;
              inherit nixpkgs;
              meisterstack = self;
            };
            cfg = foreign.nixosConfigurations.foreign.config;
          in
          pkgs.runCommand "foreign-flake-imports-us" { } ''
            grep -qx 'MEISTER_ROLE=agent,cluster,cloud,addons' \
              ${cfg.environment.etc."meisterstack/context.env".source}
            grep -q metrics_listen ${cfg.environment.etc."meisterstack/cloud.toml".source}
            touch $out
          '';
      };
    };
}
