# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Check that etcd systemd readiness does not require a Raft leader, allowing
# the first member of a new group to start. Automatic restart remains required.
{ nixpkgs, lib, pkgs, system, self }:

let
  etcdUnit = extra: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        nixpkgs.overlays = [ self.overlays.default ];
        networking.hostName = "cp1";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.managed
      {
        meisterstack.roles = [ "cloud" ];
        meisterstack.managed.enable = true;
        meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
        meisterstack.etcd.enable = true;
      }
      extra
    ];
  }).config.systemd.services.etcd;

  clustered = etcdUnit {
    meisterstack.etcd.member = "cp1";
    meisterstack.etcd.peers = {
      cp1 = "10.128.1.119";
      cp2 = "10.128.1.120";
      cp3 = "10.128.1.121";
    };
    meisterstack.etcd.clusterToken = "probe";
  };
  alone = etcdUnit { };

  bad =
    lib.optional (clustered.serviceConfig.Type or "notify" == "notify")
      ("a member of a three-peer raft waits for a LEADER before it calls "
        + "itself started, and the first member of a fresh cluster never has "
        + "one: its activation times out and the rollout stops")
    ++ lib.optional (alone.serviceConfig.Type or "notify" == "notify")
      "a single-member etcd waits for readiness it also has to produce alone"
    # The half that must NOT move with it: a unit that gives up on its peers
    # has to come back and keep trying.
    ++ lib.optional ((clustered.serviceConfig.Restart or "") != "always")
      "the etcd unit no longer restarts, so a member that started before its peers stays down";
in
pkgs.runCommand "raft-member-starts-alone" { } (
  if bad == [ ] then ''
    echo "an etcd member starts without waiting for a cluster it cannot form alone"
    touch $out
  '' else ''
    ${lib.concatMapStrings (l: "echo ${lib.escapeShellArg l}\n") bad}
    echo "-> nix/etcd.nix: systemd.services.etcd.serviceConfig.Type (lane L4)"
    exit 1
  ''
)
