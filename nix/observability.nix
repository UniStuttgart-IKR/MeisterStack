# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Configure Alloy for journal forwarding. Binaries export traces directly and
# metrics use separate listeners. The unit waits for its configuration file,
# which only a boot renderer writes, so only such a host runs it by default.
# A host that runs its own Alloy keeps it: asking for both is refused.
{ lib, pkgs, config, options, ... }:
let
  cfg = config.meisterstack;

  # Weaker than any mkDefault, so that a host's own definition of
  # services.alloy always wins the merge and is listed by the refusal below
  # instead of being merged away silently.
  ownedWeakly = lib.mkOverride 1400;

  # Every definition of a services.alloy option that this file did not write.
  hostDefinitionsOf = opt:
    lib.filter (d: d.file != toString ./observability.nix) opt.definitionsWithLocations;
  hostAlloyFiles = lib.unique (map (d: d.file)
    (hostDefinitionsOf options.services.alloy.enable
      ++ hostDefinitionsOf options.services.alloy.configPath));
in
{
  options.meisterstack.observability.enable = lib.mkOption {
    type = lib.types.bool;
    default = cfg.context.enable;
    defaultText = lib.literalExpression "config.meisterstack.context.enable";
    description = ''
      Whether this machine runs the log collector beside its units, as
      `services.alloy`, reading `<configDir>/alloy.alloy`. It ships the WHOLE
      journal — the interesting lines are often not ours: etcd losing a
      leader, the VMM refusing a disk, the kernel remounting read-only.

      Off unless a boot renderer is imported, because that renderer is the
      only author of the collector's config: a store-built host would have to
      bake it at build time, which is not built yet, and on any other host
      `services.alloy` may already be the host's own collector. Turning this
      on where the host configures `services.alloy` itself is refused at
      evaluation instead of silently replacing the host's `configPath`.
    '';
  };

  config = lib.mkIf cfg.observability.enable {
    assertions = [{
      assertion = hostAlloyFiles == [ ];
      message =
        "meisterstack.observability.enable runs this stack's log collector as "
        + "services.alloy, and this host configures services.alloy itself (in "
        + lib.concatStringsSep ", " hostAlloyFiles + "). A host has one Alloy: "
        + "turn meisterstack.observability.enable off and ship the journal with the "
        + "host's own, or drop the host's definition.";
    }];

    services.alloy = {
      enable = ownedWeakly true;
      # Read the selected configuration file; runtime files do not participate in
      # the NixOS module's environment.etc reload triggers.
      configPath = ownedWeakly "${cfg.configDir}/alloy.alloy";
      extraFlags = [
        # Bind the collector UI and internal metrics to loopback.
        "--server.http.listen-addr=127.0.0.1:12345"
        # Disable anonymous usage reporting.
        "--disable-reporting"
      ];
    };

    systemd.services.alloy = {
      # Evaluate the configuration-file condition after the renderer when present.
      after = [ "meister-context.service" ];
      wants = lib.mkIf cfg.context.enable [ "meister-context.service" ];
      unitConfig.ConditionPathExists = "${cfg.configDir}/alloy.alloy";
    };

    # Provide Alloy configuration validation tools for operators.
    environment.systemPackages = [ pkgs.grafana-alloy ];
  };
}
