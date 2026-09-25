# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Operator policy used by the example fleets.
# Service modules leave stateVersion, mounts, firewall and host hardware to these profiles.
{ lib, ... }:
{
  base = { config, lib, pkgs, ... }: {
    # Example initial NixOS state version.
    system.stateVersion = "25.11";

    # Install layouts provide mounts through disko. Existing hosts use adopted below.

    # Example firewall policy; adjust exposed ports to the site.
    networking.firewall.enable = true;
    networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
      cloud.api
      cloud.grpc
      cluster.api
      cluster.grpc
      etcd.peer
    ];

    # Placeholder public signing key; replace it before deployment.
    meisterstack.managed.trustedPublicKeys = [
      "example-fleet-not-a-real-key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
  };

  # Mounts for existing hosts without an install layout.
  adopted = { ... }: {
    fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
    fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
  };

  controller = { ... }: {
    # Use a labelled data device for controller state.
    meisterstack.data.label = lib.mkDefault "meister-data";
  };

  compute-cpu = { ... }: {
    # Disable unused fabric services on CPU-only hosts.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
  };
  # Standalone profile with one authorized local operator.
  single-node = { ... }: {
    meisterstack.singleNode.enable = true;
    meisterstack.singleNode.operators = [ "operator" ];
    users.users.operator = { isNormalUser = true; };
    # Standalone mode does not require these fabric services.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
  };
}
