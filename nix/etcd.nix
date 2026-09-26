# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Run a local etcd member for controller roles. Clients use loopback; optional
# static peers use the configured management addresses. Data can live on a
# separate filesystem. This module does not configure peer TLS.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack.etcd;
  clustered = cfg.peers != { };
  selfIp = cfg.peers.${cfg.member} or "127.0.0.1";
in
{
  options.meisterstack.etcd = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = builtins.any (r: r == "cloud" || r == "cluster")
        config.meisterstack.unitsFor;
      defaultText = lib.literalExpression ''a controller tier runs one'';
      description = ''
        Whether this machine runs the etcd its controller talks to. The
        default is "yes if it carries a controller role": each tier's etcd is
        private to its controller (Oakestra-style), so an agent-only node has
        no reason to run one — and a host that imports these modules without
        naming a role gets no database it did not ask for.

        The appliance image is every tier at once (`meisterstack.unitsFor`),
        so there this is on, exactly as it has always been.
      '';
    };

    peers = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        cluster-a = "10.128.1.104";
        cluster-b = "10.128.1.105";
        cluster-c = "10.128.1.106";
      };
      description = ''
        Member name -> IP of every etcd member of this tier, this VM included.
        Empty (the default) keeps the single loopback member. Three members
        tolerate one loss; two do not tolerate any, so an even count buys
        nothing.
      '';
    };
    member = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      description = "Which entry of `peers` this VM is.";
    };
    clusterToken = lib.mkOption {
      type = lib.types.str;
      default = "meisterstack";
      description = ''
        Bootstrap token. Two tiers bootstrapping on one network must not share
        it — it is what keeps a cloud member from joining a cluster's Raft.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Provide etcdctl for local health and membership inspection.
    environment.systemPackages = [ pkgs.etcd ];

    assertions = [
      {
        assertion = !clustered || cfg.peers ? ${cfg.member};
        message =
          "meisterstack.etcd.member '${cfg.member}' is not in meisterstack.etcd.peers "
          + "(${toString (lib.attrNames cfg.peers)}); this VM would bootstrap as a "
          + "member the others never invited.";
      }
    ];

    services.etcd = {
      enable = true;
      # Keep client access local even when peer replication spans hosts.
      listenClientUrls = [ "http://127.0.0.1:2379" ];
      advertiseClientUrls = [ "http://127.0.0.1:2379" ];
      # Compact revision history after one hour to bound retained watch history.
      # Consumers must recover from compacted watch revisions by relisting.
      extraConf = {
        AUTO_COMPACTION_MODE = "periodic";
        AUTO_COMPACTION_RETENTION = "1h";
      };
    } // lib.optionalAttrs clustered {
      name = cfg.member;
      listenPeerUrls = [ "http://${selfIp}:2380" ];
      initialAdvertisePeerUrls = [ "http://${selfIp}:2380" ];
      initialCluster = lib.mapAttrsToList (n: ip: "${n}=http://${ip}:2380") cfg.peers;
      initialClusterState = "new";
      initialClusterToken = cfg.clusterToken;
    };

    # Use process startup as systemd readiness. Waiting for a Raft leader would
    # block the first member of a new multi-member group and prevent sequential
    # bootstrap. Deployment health checks separately require a working quorum.
    # Keep automatic restart so early members continue trying as peers arrive.
    fileSystems."/var/lib/etcd" = lib.mkIf (config.meisterstack.data.label == "etcd-data") {
      device = "/dev/disk/by-label/etcd-data";
      fsType = "ext4";
      options = [ "nofail" "x-systemd.device-timeout=5s" ];
    };

    # Allow an optional runtime environment file to supply context-based membership.
    systemd.services.etcd = lib.mkMerge [
      # Apply the same process-readiness policy to this unit variant.
      { serviceConfig.Type = lib.mkForce "exec"; }
      (lib.mkIf config.meisterstack.context.enable {
        after = [ "meister-context.service" ];
        serviceConfig.EnvironmentFile = "-${config.meisterstack.configDir}/etcd.env";
      })
    ];
  };
}
