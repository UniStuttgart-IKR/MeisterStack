# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Configure Alloy for journal forwarding. Binaries export traces directly and
# metrics use separate listeners. The unit waits for its configuration file;
# managed hosts disable it by default until that file is supplied.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
in
{
  options.meisterstack.observability.enable = lib.mkOption {
    type = lib.types.bool;
    default = cfg.unitsFor != [ ];
    defaultText = lib.literalExpression ''a machine that runs a role collects its journal'';
    description = ''
      Whether this machine runs the log collector beside its units.

      The default is "yes, if this machine runs any of our units at all": the
      interesting lines on these VMs are not ours — etcd losing a leader, the
      VMM refusing a disk, the kernel remounting read-only — and it is the
      WHOLE journal that gets shipped, which is the entire reason to run a
      collector rather than teach three binaries to push.

      It still costs nothing on a machine that names no Loki: without a
      rendered config the unit's ConditionPathExists is not met and Alloy
      stays skipped.

      A managed host turns this off by default, and that is a gap rather
      than a decision: its config file would have to be baked at build time
      the way its TOML files are, and that is not built yet.
    '';
  };

  config = lib.mkIf cfg.observability.enable {
    services.alloy = {
      enable = true;
      # Read the selected configuration file; runtime files do not participate in
      # the NixOS module's environment.etc reload triggers.
      configPath = "${cfg.configDir}/alloy.alloy";
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
