# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# What this machine is, and the values it would otherwise have been handed at
# boot. Two roads reach `one-context`, and this module is the second one.
#
# The lab's VMs are told what they are by an OpenNebula CONTEXT: MEISTER_ROLE
# and a dozen MEISTER_* variables, read from a cd at boot. A box installed from
# this flake — a plan node, or somebody else's NixOS host that imports
# `nixosModules.default` — has no cd and no OpenNebula, and it should not need
# a second renderer for that. So the same variables are BAKED into
# /etc/meisterstack/context.env, and one-context sources that file before it
# looks for the cd: the plan supplies the defaults, a real context overrides
# them, and there is exactly one piece of code that turns a variable into a
# config file.
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
        image: every unit ships, and MEISTER_ROLE in the OpenNebula context
        decides at boot which of them starts. A non-empty list is baked as
        that variable's default, so a machine with no context still knows what
        it is — and a context may still override it.

        `both` and `all` are MEISTER_ROLE shorthands and not values here: a
        configuration that knows its roles at build time can name them.
      '';
    };

    context.defaults = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        MEISTER_CLUSTER_NAME = "cluster-1";
        MEISTER_LOKI_URL = "http://10.0.0.10:3100/loki/api/v1/push";
      };
      description = ''
        MEISTER_* variables baked as defaults for one-context. Anything the
        OpenNebula context can say, a configuration can say here instead —
        and the context, being the thing that knows where this machine was
        actually booted, wins over it.

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

    # Shell, because the file is sourced by a shell — the same shell that
    # sources the context's own context.sh, so that both roads arrive at
    # one-context in the same shape. Quoted through escapeShellArg: a Loki url
    # with a `&` in it is a value, not a job control character.
    # No defaults, no file — and one-context reads exactly that: the generic
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
