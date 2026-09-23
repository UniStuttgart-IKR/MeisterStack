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
# Until M5B a second, boot-time renderer read the same variables and
# `checks.render-parity` held the two to each other; that renderer went to
# `~/git/meisterstack-lab/legacy/nix/` with the appliance image.
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
        Whether this machine renders its config files at BOOT, from a
        context. A renderer sets it by being imported; this flake ships none
        any more (M5B), so on a host of this flake it is always false and
        what reads it is the refusal in nix/managed.nix.

        It is read rather than set: the two auth fragments of the cloud exist
        only where something appends them, and `nix/managed.nix` refuses to
        be combined with a renderer — a host whose config files are complete
        at build time must not have a second author for them at boot.
      '';
    };

    # --- lane 5B: the one option the boot renderer used to declare ------
    #
    # `nix/context.nix` declared it and went with M5B. It stays because
    # `nix/provider-opennebula.nix` sets it and that module is NOT legacy: a
    # machine of this fleet can still be instantiated on OpenNebula, and
    # then something has to read the medium it was handed.
    #
    # `context.sources` did NOT come along: it was the renderer's own list
    # of files to read, nothing outside `nix/context.nix` ever set it or
    # read it, and a declared option with no reader is a promise nobody
    # keeps (measured against the merged tree, 2026-09-23).
    #
    # NOTE FOR THE MERGE: lane 5C moves this same declaration here for the
    # same reason (its finding N5, `managed-may-read-its-provider`) and
    # brings the CONSUMER with it — a minimal `meister-provider-context.service`
    # in nix/services.nix. Keep 5C's block and drop this one; this block is
    # a strict subset of it.
    context.providerScript = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = ''
        Shell run before anything else reads a context: a provider's chance
        to say where this machine was booted.

        Empty (the default) is a machine whose whole context is its baked
        files. `nixosModules.provider-opennebula` is the one implementation
        today, and it is deliberately NOT part of `nixosModules.default`: a
        reader that knows how to mount a CONTEXT cd is a reader that cannot
        be used anywhere else.

        What it may do is set MEISTER_* variables and configure the
        interface it owns. What it must not do is render a config file.
      '';
    };
    # --- end lane 5B ---------------------------------------------------

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
