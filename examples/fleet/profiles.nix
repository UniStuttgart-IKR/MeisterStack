# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The profiles of the worked example, and they are the OPERATOR's half.
#
# `lib.mkFleet` takes an attrset like this one and gives each host the
# profiles its inventory entry names (`[defaults] profiles`, a group's, its
# own). Everything in here is a decision about a MACHINE rather than about
# MeisterStack — `system.stateVersion`, the filesystems, sshd, the firewall —
# which is exactly the half `nixosModules.services` refuses to make
# (`checks.services-are-pure`).
#
# templates/operator/profiles/ is the same set, written for somebody who is
# starting a fleet of their own; this copy is what `nix flake check` builds.
{ lib, ... }:
{
  base = { config, lib, pkgs, ... }: {
    # The host's own answer to "which NixOS did this machine's state start
    # on". Ours would be 25.11, and a module of ours that set it could not
    # be imported into a host that already has one.
    system.stateVersion = "25.11";

    # Where this example's systems live once they are on a disk. Until M3
    # brings disko, the plan says nothing about partitions and the host
    # module does — which is the honest split: a label is a fact about a
    # disk somebody already partitioned.
    fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
    fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };

    # The example fleet is a lab on one switch; a real operator's base
    # profile is where their own rules go. What matters here is that the
    # decision is VISIBLE and is theirs: `meisterstack.ports` publishes the
    # numbers, and this is what names them.
    networking.firewall.enable = true;
    networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
      cloud.api
      cloud.grpc
      cluster.api
      cluster.grpc
      etcd.peer
    ];

    # The signing key whose closures these hosts accept. An EXAMPLE key name
    # and not a usable one: `nix copy --to ssh-ng://` needs the public half
    # of the key `meister-deploy build --sign-key` signs with (measured, M0
    # probe S12), and a fleet that is really deployed replaces this line
    # with its own. templates/operator ships NO key at all, for the same
    # reason a template ships no certificate.
    meisterstack.managed.trustedPublicKeys = [
      "example-fleet-not-a-real-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
  };

  controller = { ... }: {
    # A controller keeps etcd's state on its own block device, by LABEL: which
    # slot a disk lands in is not a promise anybody made.
    meisterstack.data.label = lib.mkDefault "meister-data";
  };

  compute-cpu = { ... }: {
    # A CPU-only carrier: no GPU packages, no Leandro input, and that is the
    # point of this profile existing at all — the fleet has to build without
    # anybody's home directory (L01/V04).
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
  };
}
