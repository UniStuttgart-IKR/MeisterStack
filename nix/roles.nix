# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Declare runtime roles and shared context inputs. Role selection controls
# which units are available; provider initialization is independent of optional
# configuration rendering.
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
        what reads it is the refusal in nix/store-host.nix.

        It is read rather than set: the two auth fragments of the cloud exist
        only where something appends them, and `nix/store-host.nix` refuses to
        be combined with a renderer — a host whose config files are complete
        at build time must not have a second author for them at boot.
      '';
    };

    # Declare provider initialization here so store-built hosts can use it without
    # importing a boot-time configuration renderer.
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
        files. On a store-built host there is no renderer — the config files
        are part of the system generation — and
        `meister-provider-context.service` (nix/services.nix) runs the same
        script for the one thing that is still the provider's to say: the
        machine's address, its route, its resolver, its hostname and the
        operator's key.

        What it may do is set MEISTER_* variables and configure the
        interface it owns. What it must not do is render a config file.
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
        MEISTER_* variables baked as defaults for the context renderer.
        Anything a provider's context can say, a configuration can say here
        instead — and the context, being the thing that knows where this
        machine was actually booted, wins over it.

        On a store-built host this attrset is the WHOLE input: there is no
        provider and no cd, `nix/lib/render.nix` turns it into the complete
        config files at build time, and nothing overrides it afterwards.

        Secrets do not belong here: this file is in the nix store and the
        store is world-readable. Certificates and keys travel outside the
        store, as they always have.
      '';
    };
  };

  config = {
    # Derive the role variable from `roles`, apart from the other context defaults.
    meisterstack.context.defaults = lib.mkIf (cfg.roles != [ ]) {
      MEISTER_ROLE = lib.concatStringsSep "," cfg.roles;
    };

    # Escape values for the shell environment file consumed by context-based hosts.
    environment.etc."meisterstack/context.env" = lib.mkIf (cfg.context.defaults != { }) {
      text =
        lib.concatStringsSep "\n"
          (lib.mapAttrsToList (n: v: "${n}=${lib.escapeShellArg v}") cfg.context.defaults)
        + "\n";
    };
  };
}
