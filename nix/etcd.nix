# The tier's etcd. Single-member and loopback-only by default: the controller
# on the same VM is the only client (Oakestra-style — each tier's etcd is
# private to its controller).
#
# `meisterstack.etcd.peers` turns the same module into one member of a static
# three-member cluster, which is what the leaderless HA of the design needs:
# one logical etcd per tier, a member next to every controller replica, Raft
# between them, and every controller still talking to its own 127.0.0.1. Only
# peer traffic goes over the VM IP. Empty peers = exactly the single member of
# before, so the existing image is unchanged until someone sets the option.
#
# Static bootstrap on purpose: the members are known when the lab is laid out,
# so `initial-cluster` names all three and nothing has to discover anything.
# The price is that the peer set is build-time — this member's name must be
# `member` (default: the hostname baked into the image), which means one
# nixosConfiguration per control-plane VM rather than the one role-agnostic
# image the single-member lab shares today.
#
# Optional persistence: attach a second disk in OpenNebula, mkfs.ext4 once,
# and /var/lib/etcd survives image updates; without it the mount is skipped
# (nofail) and etcd lives on the root disk.
{ lib, config, ... }:
let
  cfg = config.meisterstack.etcd;
  clustered = cfg.peers != { };
  selfIp = cfg.peers.${cfg.member} or "127.0.0.1";
in
{
  options.meisterstack.etcd = {
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

  config = {
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
      # Clients stay local in both shapes: the controller next to this member
      # is the only one, and a replica that loses quorum should stall on its
      # own member rather than quietly write through a healthy neighbour.
      listenClientUrls = [ "http://127.0.0.1:2379" ];
      advertiseClientUrls = [ "http://127.0.0.1:2379" ];
      # Keep an hour of history and no more.
      #
      # etcd keeps EVERY revision until somebody compacts, and nothing in
      # this stack was that somebody. A control plane writes a revision per
      # heartbeat per node per pass — the lab writes some hundreds a minute
      # doing nothing at all — so the store grows without bound and stops at
      # the 2 GiB default quota with `mvcc: database space exceeded`. Then
      # NOTHING can be written: no vm create, no delete, no phase, and the
      # only symptom above is that objects stop moving. That is where a day
      # of chaos runs put this lab on 2026-09-10, and getting out of it was
      # compact, restart (to drop the failed defrag's temp file, which had
      # itself filled the disk), defrag, disarm — three times.
      #
      # An hour is the same order as the objects it protects: nothing here
      # reads a revision older than the pass that wrote it, and the one thing
      # that would — a watch that reconnects with an old revision — falls back
      # to a fresh list. Periodic and not revision-based, because the number
      # of revisions per hour is a property of the fleet's size and the
      # retention should not be.
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

    # By label, not by device name: which slot the datablock lands in depends
    # on the OS image's DEV_PREFIX and the attach order — /dev/vdb silently
    # became sda+vda twice in the lab, and etcd silently lived on the root
    # disk. The label is IN the filesystem (mkfs.ext4 -L etcd-data, or
    # e2label once), so it survives image swaps and bus surprises alike.
    #
    # Only in the historical shape. `meisterstack.data.label = "meister-data"`
    # (nix/data.nix) mounts ONE block for etcd and the addons together and
    # points etcd at a subdirectory of it instead; two fileSystems entries for
    # one mount point would be a conflict rather than a choice.
    fileSystems."/var/lib/etcd" = lib.mkIf (config.meisterstack.data.label == "etcd-data") {
      device = "/dev/disk/by-label/etcd-data";
      fsType = "ext4";
      options = [ "nofail" "x-systemd.device-timeout=5s" ];
    };

    # The runtime twin of `peers`: one-context renders ETCD_* into this file
    # from MEISTER_ETCD_PEERS/_MEMBER/_TOKEN. EnvironmentFile overrides the
    # module's Environment=, so a context-driven lab clusters the SAME
    # role-agnostic image that build-time `peers` clusters for NixOS-first
    # deployments. Absent file (the `-`) = exactly the baked behaviour.
    systemd.services.etcd = {
      after = [ "one-context.service" ];
      serviceConfig.EnvironmentFile = "-/run/meisterstack/etcd.env";
    };
  };
}
