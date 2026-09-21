# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The log collector. Traces leave this VM over OTLP straight from the
# binaries (MEISTER_OTLP_ENDPOINT, nix/context.nix) and metrics are
# SCRAPED off the three metrics ports — so what is left for a collector is
# the third signal, and Alloy is here for that one only.
#
# Why a collector at all, when every binary can already log: because the
# interesting lines on these VMs are not ours. etcd losing a leader,
# cloud-hypervisor refusing a disk, nftables, sshd, the kernel remounting
# read-only — every incident this lab has had was diagnosed in the journal
# next to our lines, not in them. `loki.source.journal` takes the WHOLE
# journal, which is the entire reason to run a collector instead of teaching
# three binaries to push.
#
# Explicitly NOT an OTLP hop: the binaries send spans to Tempo themselves.
# Routing them through Alloy would add a process that can be down between a
# trace and its collector, and buy nothing at this size.
#
# Off unless the deployment asks for it. The context renderer writes
# <configDir>/alloy.alloy only when MEISTER_LOKI_URL is in the context, and
# the unit's ConditionPathExists reads that file: no variable, no config, no
# Alloy. A VM that says nothing runs exactly what it ran yesterday.
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
      # A single FILE rather than the module's /etc/alloy default, because this
      # config is rendered per VM at boot (host label, role label, the Loki url
      # itself) and /etc on this image is the nix store. The cost is config
      # reload — the module wires reloadTriggers to `environment.etc` entries,
      # and a store path is not what we point at — which is the right trade for
      # a fleet that gets a new config by rebooting into a new context anyway.
      configPath = "${cfg.configDir}/alloy.alloy";
      extraFlags = [
        # The ui and the collector's own scrape endpoint on loopback. The
        # module's default binds 0.0.0.0:12345, and this image already has
        # three unauthenticated metrics ports the lab knows about; a fourth
        # that nobody asked for should not be one of them.
        "--server.http.listen-addr=127.0.0.1:12345"
        # No phone-home. This is a lab VM in someone's thesis, not a
        # deployment anybody needs usage statistics about.
        "--disable-reporting"
      ];
    };

    systemd.services.alloy = {
      # The config does not exist until the renderer has read the context
      # drive and written it. Without this ordering the condition below is
      # evaluated on a file that is about to appear, and Alloy stays skipped
      # until somebody notices.
      #
      # `after` unconditionally and `wants` only where the renderer exists:
      # ordering against a unit that is not on this machine is a no-op, while
      # WANTING one that does not exist is a job systemd cannot satisfy.
      after = [ "meister-context.service" ];
      wants = lib.mkIf cfg.context.enable [ "meister-context.service" ];
      unitConfig.ConditionPathExists = "${cfg.configDir}/alloy.alloy";
    };

    # `alloy fmt`/`alloy validate` on the box, for the same reason etcdctl is
    # in nix/appliance.nix: the file this unit reads is generated, and the
    # first question about a collector that is not shipping is whether its
    # config parses.
    environment.systemPackages = [ pkgs.grafana-alloy ];
  };
}
