# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# What this machine is, and the values it would otherwise have been handed at
# boot. Two roads reach the context renderer (nix/context.nix), and this
# module is the second one.
#
# The lab's VMs are told what they are by their provider's CONTEXT:
# MEISTER_ROLE and a dozen MEISTER_* variables, read from a cd at boot. A box
# installed from this flake — a plan node, or somebody else's NixOS host that
# imports `nixosModules.default` — has no cd and no provider, and it should
# not need a second renderer for that. So the same variables are BAKED into
# /etc/meisterstack/context.env, and the renderer sources that file before it
# lets a provider speak: the plan supplies the defaults, a real context
# overrides them, and there is exactly one piece of code that turns a
# variable into a config file.
#
# The THIRD road is `nix/managed.nix`: there the same variables are read by
# `nix/lib/render.nix` at build time and the config files are complete before
# the machine boots. Same input, same keys, no renderer — and
# `checks.render-parity` holds the two to each other.
#
#   imports = [ meisterstack.nixosModules.default ];
#   meisterstack.roles = [ "cloud" "cluster" ];
#   meisterstack.cloud.settings = { ... };
#
# is therefore a complete MeisterStack host, with no image and no meister-deploy.
{ lib, config, ... }:
let
  cfg = config.meisterstack;
in
{
  options.meisterstack = {
    roles = lib.mkOption {
      type = lib.types.listOf (lib.types.enum [ "cloud" "cluster" "agent" "addons" ]);
      default = [ ];
      example = [ "cloud" "cluster" "addons" ];
      description = ''
        Which roles this machine runs. Empty (the default) is the generic
        appliance image: every unit ships, and MEISTER_ROLE in the context
        decides at boot which of them starts. A non-empty list is baked as
        that variable's default, so a machine with no context still knows what
        it is — and a context may still override it.

        On every host that is not that image, this list is also what decides
        which UNITS are built at all (`meisterstack.unitsFor`): a cloud is not
        a machine with an agent unit that happens to be stopped.

        `both` and `all` are MEISTER_ROLE shorthands and not values here: a
        configuration that knows its roles at build time can name them.
      '';
    };

    context.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether this machine renders its config files at BOOT, from a context
        (nix/context.nix sets this, by being imported).

        It is read rather than set: the two auth fragments of the cloud exist
        only where something appends them, and `nix/managed.nix` refuses to
        be combined with a renderer — a host whose config files are complete
        at build time must not have a second author for them at boot.
      '';
    };

    # --- lane 5C ---
    # Declared HERE and not in nix/context.nix, which is where it used to
    # live and where it is still read.
    #
    # The reason is a host the lab built: a managed NixOS host on an
    # OpenNebula VM. It needs the strict reader
    # (`nixosModules.provider-opennebula`) to learn its address, its
    # hostname and its resolver off the CONTEXT cd, and it must NOT have
    # the boot renderer, because nix/managed.nix asserts against it — a
    # machine whose config files are a system generation may not have a
    # second author for them at boot. The reader sets this option, the
    # renderer declared it, and nix/managed.nix forbids the renderer: the
    # combination did not evaluate at all, and the lab paid for it with
    # thirty hand-written lines of unit in the operator's own repository
    # (L2 finding N5, 2026-09-23).
    #
    # A declaration decides nothing, so moving it into the module every
    # host imports costs nothing either: `checks.services-are-pure` is
    # about what nix/services.nix SETS, and this sets nothing.
    context.providerScript = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Shell run before anything else reads this machine's context: a
        provider's chance to say where the machine was actually booted.

        Empty (the default) is a machine whose whole context is what its
        configuration bakes. `nixosModules.provider-opennebula` is the one
        implementation today, and it is deliberately NOT part of
        `nixosModules.default`: a reader that knows how to mount a CONTEXT
        cd is a reader nobody else can use.

        Two modules run it, and never both on one host. On an appliance the
        boot renderer (nix/context.nix) runs it in the middle of rendering,
        because there the provider's values are an INPUT to the config
        files. On a managed host there is no renderer — the config files
        are part of the system generation — and
        `meister-provider-context.service` (nix/services.nix) runs the same
        script for the one thing that is still the provider's to say: the
        machine's address, its route, its resolver, its hostname and the
        operator's key.

        What it may do is set MEISTER_* variables and configure the
        interface it owns. What it must not do is render a config file.
      '';
    };
    # --- end lane 5C ---

    context.defaults = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        MEISTER_CLUSTER_NAME = "cluster-1";
        MEISTER_LOKI_URL = "http://10.0.0.10:3100/loki/api/v1/push";
      };
      description = ''
        MEISTER_* variables baked as defaults for the context renderer.
        Anything a provider's context can say, a configuration can say here
        instead — and the context, being the thing that knows where this
        machine was actually booted, wins over it.

        On a managed host this attrset is the WHOLE input: there is no
        provider and no cd, `nix/lib/render.nix` turns it into the complete
        config files at build time, and nothing overrides it afterwards.

        Secrets do not belong here: this file is in the nix store and the
        store is world-readable. Certificates and keys travel with
        `meister-deploy keys push`, as they always have.
      '';
    };
  };

  config = {
    # Disjoint from what a plan writes into `context.defaults`, on purpose:
    # two definitions of one variable would be a conflict rather than a
    # precedence, and MEISTER_ROLE has exactly one owner here.
    meisterstack.context.defaults = lib.mkIf (cfg.roles != [ ]) {
      MEISTER_ROLE = lib.concatStringsSep "," cfg.roles;
    };

    # Shell, because the file is sourced by a shell — the same shell the
    # renderer runs in, so that both roads arrive there in the same shape.
    # Quoted through escapeShellArg: a Loki url with a `&` in it is a value,
    # not a job control character.
    # No defaults, no file — and the renderer reads exactly that: the generic
    # image, which is told everything at boot, carries nothing it would have
    # to be told to ignore.
    environment.etc."meisterstack/context.env" = lib.mkIf (cfg.context.defaults != { }) {
      text =
        lib.concatStringsSep "\n"
          (lib.mapAttrsToList (n: v: "${n}=${lib.escapeShellArg v}") cfg.context.defaults)
        + "\n";
    };
  };
}
