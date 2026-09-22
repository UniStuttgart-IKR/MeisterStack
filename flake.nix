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
      # With this repository's own packages in it (nix/overlay.nix): the
      # modules reach them through `pkgs.meisterstack`, so the flake that
      # declares them has to be evaluating a nixpkgs that has them.
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
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
      #
      # `appliance` and not `default` since M1: `default` is the SERVICES, and
      # they decide nothing about the machine — no stateVersion, no firewall,
      # no console, and no units at all without a role. This image is a whole
      # machine and needs all of it, which is what the appliance profile is
      # (nix/appliance.nix, and it pulls in the renderer and the provider).
      genericModules = [ self.nixosModules.appliance ];

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
      #              complete at build time, no renderer.
      #   context    the boot renderer on its own, for a host that wants one
      #              without the rest of the appliance.
      #
      # The single service modules (etcd, controllers, agent, …) are NOT
      # exported any more. They stopped standing on their own in M1: they
      # read `meisterstack.unitsFor`, `binDir`, `pki.dir` and `configDir`,
      # which nix/services.nix declares, and an export that only works next
      # to another export is a promise that cannot be kept.
      nixosModules = {
        services = ./nix/services.nix;
        managed = ./nix/managed.nix;
        appliance = ./nix/appliance.nix;
        context = ./nix/context.nix;
        provider-opennebula = ./nix/provider-opennebula.nix;
        default = self.nixosModules.services;
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
      # What this repository builds, for a nixpkgs that is not ours.
      #
      #   nixpkgs.overlays = [ meisterstack.overlays.default ];
      #   environment.systemPackages = [ pkgs.meisterstack ];
      #
      # nix/overlay.nix says why it is an overlay rather than only the
      # `packages` output below.
      overlays.default = import ./nix/overlay.nix;

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

        # The options a foreign host sees. A configuration that imports
        # `nixosModules.default` gets option NAMES and nothing else — no brief,
        # no worked example — so the module's own descriptions are the
        # documentation, and this output is how they leave the module without
        # being retyped anywhere. scripts/module-options.sh turns it into the
        # table in deploy/README.md and checks that the table is still current.
        module-options =
          let
            evaluated = nixpkgs.lib.nixosSystem {
              # The appliance plus `managed`: the table documents every
              # option this flake exports, and the two profiles are mutually
              # exclusive only in their `enable`, not in their declarations.
              # Without this line the managed half of the stack would have no
              # documentation at all.
              modules = genericModules ++ [ self.nixosModules.managed ] ++ [{
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
        # nix/services.nix decides nothing about the machine, and this is
        # what holds it to that. A minimal host is evaluated three times —
        # without our modules, with them and no role, and with them and the
        # agent role — and the attributes below have to come out the same.
        #
        # They are not a taste: each one is a decision somebody else's NixOS
        # configuration has already made. A module that sets `stateVersion`,
        # turns a firewall off or names a bootloader cannot be imported into
        # a host that is not ours, and `nixosModules.default` is exactly
        # that import.
        #
        # With no role the list is longer, because a machine that carries no
        # unit of ours should carry no etcd, no collector, no routing daemon,
        # no kernel module and no mount of ours either.
        services-are-pure =
          let
            probe = modules: (nixpkgs.lib.nixosSystem {
              modules = [{ nixpkgs.hostPlatform = system; }] ++ modules;
            }).config;

            bare = probe [ ];
            noRole = probe [ self.nixosModules.services ];
            agentRole = probe [
              self.nixosModules.services
              { meisterstack.roles = [ "agent" ]; }
            ];

            hostGlobal = c: {
              "networking.useDHCP" = c.networking.useDHCP;
              "networking.firewall.enable" = c.networking.firewall.enable;
              "networking.resolvconf.enable" = c.networking.resolvconf.enable;
              "networking.usePredictableInterfaceNames" =
                c.networking.usePredictableInterfaceNames;
              "nix.enable" = c.nix.enable;
              "system.stateVersion" = c.system.stateVersion;
              "boot.kernelParams" = c.boot.kernelParams;
              "boot.loader.grub.enable" = c.boot.loader.grub.enable;
              "boot.loader.grub.device" = c.boot.loader.grub.device;
              "boot.loader.systemd-boot.enable" = c.boot.loader.systemd-boot.enable;
              "boot.loader.efi.canTouchEfiVariables" =
                c.boot.loader.efi.canTouchEfiVariables;
            };

            roleLess = c: hostGlobal c // {
              "services.etcd.enable" = c.services.etcd.enable;
              "services.alloy.enable" = c.services.alloy.enable;
              "services.frr.bgpd.enable" = c.services.frr.bgpd.enable;
              "boot.kernelModules" = c.boot.kernelModules;
              "fileSystems" = lib.attrNames c.fileSystems;
            };

            differing = f: a: b:
              lib.filter (k: (f a).${k} != (f b).${k}) (lib.attrNames (f a));

            bad =
              map (k: "with no role, ${k} is not what it was") (differing roleLess bare noRole)
              ++ map (k: "with the agent role, ${k} is not what it was")
                (differing hostGlobal bare agentRole);
          in
          pkgs.runCommand "services-are-pure" { } (
            if bad == [ ] then ''
              echo "nixosModules.services changed nothing host-global, with and without a role"
              touch $out
            '' else ''
              ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
              echo "-> nix/services.nix decides only what MeisterStack is, never what the machine is"
              exit 1
            ''
          );

        # Two renderers, one input, one answer.
        #
        # nix/context.nix completes the config files while the machine boots;
        # nix/lib/render.nix does the same at build time for a managed host.
        # This check takes ONE node of the example plan, runs the boot
        # renderer's own script text against that node's context.env, and
        # compares the result with the file Nix wrote — as parsed TOML and
        # not as text, because whitespace and key order are not the question.
        #
        # The script comes out of the built unit rather than out of the
        # source file, so what runs here is what would run on the machine,
        # provider block and all. Every absolute path it touches is
        # redirected into $TMPDIR the way scripts/check-context.sh does it,
        # and mount/umount/systemctl/ip are stubs: there is no medium in a
        # sandbox, which is exactly the shape a plan node boots in.
        render-parity =
          let
            # The managed twin of a planned node. `pki.dir` is pinned to the
            # appliance's value because the question here is what the
            # RENDERER produces, not where a managed host keeps its keys —
            # that difference is a decision of nix/managed.nix and would
            # otherwise be reported as a mismatch of `controller_ca`.
            managedFor = node: (nixpkgs.lib.nixosSystem {
              modules = [
                { nixpkgs.hostPlatform = system; }
                self.nixosModules.services
                self.nixosModules.managed
                {
                  meisterstack.managed.enable = true;
                  meisterstack.managed.trustedPublicKeys = [ "render-parity:not-a-real-key" ];
                  meisterstack.pki.dir = "/opt/meisterstack/pki";
                }
                (plan.nodeModule node)
              ] ++ node.modules;
            }).config;

            parity = node:
              let
                appliance = self.nixosConfigurations.${node.name}.config;
                managed = managedFor node;
                roles = managed.meisterstack.unitsFor;
                etcOf = c: name: c.environment.etc."meisterstack/${name}.toml".source;
              in
              ''
                echo "== ${node.name}: ${lib.concatStringsSep "," roles}"
                root=$TMPDIR/${node.name}
                mkdir -p $root/etc/meisterstack $root/run $root/bin $root/root
                for stub in mount umount systemctl ip; do
                  printf '#!/bin/sh\nexit 0\n' > $root/bin/$stub
                  chmod +x $root/bin/$stub
                done
                install -m0644 ${appliance.environment.etc."meisterstack/context.env".source} \
                  $root/etc/meisterstack/context.env
                ${lib.concatMapStrings (name: ''
                  install -m0644 ${etcOf appliance name} $root/etc/meisterstack/${name}.toml
                '') (map (r: if r == "agent" then "agent" else r) roles)}
                ${lib.optionalString (builtins.elem "cloud" roles) ''
                  install -m0644 ${appliance.environment.etc."meisterstack/cloud-auth-mtls.toml".source} \
                    $root/etc/meisterstack/cloud-auth-mtls.toml
                  install -m0644 ${appliance.environment.etc."meisterstack/cloud-auth-oidc.toml".source} \
                    $root/etc/meisterstack/cloud-auth-oidc.toml
                ''}
                echo "${node.name}" > $root/hostname
                : > $root/static-hosts

                cat ${pkgs.writeText "meister-context-${node.name}.sh"
                  appliance.systemd.services.meister-context.script} > $root/render.sh
                sed -i \
                  -e "s#/etc/meisterstack#$root/etc/meisterstack#g" \
                  -e "s#/run/meisterstack#$root/run/meisterstack#g" \
                  -e "s#/run/meister-context#$root/run/meister-context#g" \
                  -e "s#/run/one-context#$root/run/one-context#g" \
                  -e "s#/run/meister-role#$root/run/meister-role#g" \
                  -e "s#/dev/disk/by-label/CONTEXT#$root/no-such-medium#g" \
                  -e "s#/proc/sys/kernel/hostname#$root/hostname#g" \
                  -e "s#/etc/resolv.conf#$root/resolv.conf#g" \
                  -e "s#/etc/static/hosts#$root/static-hosts#g" \
                  -e "s#/etc/hosts#$root/hosts#g" \
                  -e "s#/root/.ssh#$root/root/.ssh#g" \
                  $root/render.sh
                PATH="$root/bin:$PATH" ${pkgs.bash}/bin/bash $root/render.sh > $root/render.log 2>&1 \
                  || { echo "the renderer exited non-zero:"; cat $root/render.log; exit 1; }

                ${lib.concatMapStrings (name: ''
                  python3 ${compare} ${node.name} ${name} \
                    $root/run/meisterstack/${name}.toml ${etcOf managed name}
                '') roles}
              '';

            compare = pkgs.writeText "render-parity.py" ''
              import sys, tomllib

              node, role, booted, built = sys.argv[1:5]
              with open(booted, "rb") as fh:
                  a = tomllib.load(fh)
              with open(built, "rb") as fh:
                  b = tomllib.load(fh)


              def flat(d, prefix=""):
                  out = {}
                  for k, v in d.items():
                      key = prefix + k
                      if isinstance(v, dict):
                          out.update(flat(v, key + "."))
                      else:
                          out[key] = v
                  return out


              fa, fb = flat(a), flat(b)
              bad = []
              for key in sorted(set(fa) | set(fb)):
                  if fa.get(key, "<absent>") != fb.get(key, "<absent>"):
                      bad.append("  %s: renderer %r, nix %r"
                                 % (key, fa.get(key, "<absent>"), fb.get(key, "<absent>")))
              if bad:
                  print("%s/%s.toml differs between the two renderers:" % (node, role))
                  print("\n".join(bad))
                  sys.exit(1)
              print("  ok   %s/%s.toml is the same file both ways (%d keys)" % (node, role, len(fa)))
            '';
          in
          pkgs.runCommand "render-parity"
            { nativeBuildInputs = [ pkgs.python3 ]; }
            (lib.concatMapStrings parity
              (lib.filter (n: builtins.elem n.name [ "box" "n1" ]) plan.metalNodes)
              + "touch $out\n");

        # Position 2 of lane 1B: a managed host's units name the STORE.
        #
        # The switch is one option — `meisterstack.binDir`, which
        # nix/managed.nix derives from `meisterstack.runtime` — and this
        # check is what holds it: every ExecStart of this stack, the
        # hypervisor path in the agent's config and the conditions that used
        # to wait for a push have to come out of the package. A single
        # /opt/meisterstack/bin left in a unit file would be a host that
        # waits forever for an rsync that is never coming.
        managed-uses-the-package =
          let
            probe = (nixpkgs.lib.nixosSystem {
              modules = [
                {
                  nixpkgs.hostPlatform = system;
                  nixpkgs.overlays = [ self.overlays.default ];
                  networking.hostName = "probe";
                  system.stateVersion = "25.11";
                  fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
                  boot.loader.grub.device = "nodev";
                }
                self.nixosModules.services
                self.nixosModules.managed
                {
                  meisterstack.roles = [ "cloud" "cluster" "agent" ];
                  meisterstack.managed.enable = true;
                  meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
                }
              ];
            }).config;
            top = probe.system.build.toplevel;
            runtime = probe.meisterstack.binDir;
          in
          pkgs.runCommand "managed-uses-the-package" { } ''
            units=${top}/etc/systemd/system
            if grep -rl '/opt/meisterstack/bin' $units; then
              echo "-> a managed host still takes a binary from a push directory"
              exit 1
            fi
            for u in meister-cloud-controller meister-cluster-controller meister-agent; do
              grep -q "ExecStart=${runtime}/$u " $units/$u.service                 || { echo "$u.service does not start ${runtime}/$u"; exit 1; }
              test -x ${runtime}/$u || { echo "${runtime}/$u is not there"; exit 1; }
            done
            # The agent starts guests with the hypervisor out of the SAME
            # directory, because `binDir` is a directory and its config names
            # the binary in it.
            test -x ${runtime}/cloud-hypervisor               || { echo "the hypervisor is not in ${runtime}"; exit 1; }
            grep -q '${runtime}/cloud-hypervisor'               ${probe.environment.etc."meisterstack/agent.toml".source}               || { echo "agent.toml does not name the hypervisor in binDir"; exit 1; }
            # And what the conditions say now: the keys, which are pushed on
            # both roads, and never a binary, which on this road cannot be
            # missing.
            if grep -h ConditionPathExists $units/meister-*.service | grep -q '/bin/'; then
              echo "-> a unit still waits for a binary that is part of its own system"
              grep -h ConditionPathExists $units/meister-*.service
              exit 1
            fi
            grep -q 'ConditionPathExists=.*/pki/ca.crt' $units/meister-agent.service               || { echo "the agent no longer waits for its CA"; exit 1; }
            echo "the units of a managed host name ${runtime} and nothing under /opt"
            touch $out
          '';

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

            # And the two the host decides and we must not. The example sets
            # 24.11 and a firewall ON; ours would be 25.11 and a firewall off
            # (nix/appliance.nix). If either of these lines ever reads like
            # our answer, a module of ours has started deciding something
            # that belongs to somebody else's machine.
            test '${cfg.system.stateVersion}' = '24.11' \
              || { echo "the foreign host's stateVersion is ${cfg.system.stateVersion}, not its own 24.11"; exit 1; }
            ${lib.optionalString (!cfg.networking.firewall.enable)
              "echo 'the foreign host asked for a firewall and did not get one'; exit 1"}
            touch $out
          '';
      };
    };
}
