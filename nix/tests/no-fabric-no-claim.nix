# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A node that says it has no NVMe fabric does not claim one.
#
# Measured in the lab (L2 finding N9, 2026-09-23):
# `meisterstack.agent.nvmeTcp.enable = false` took the kernel module out of
# the boot and left `[volume.nvmeof]` and `[volume.nvmeof-import]` in the
# rendered agent.toml. The agent then built the attacher, the attacher needs
# /dev/nvme-fabrics, and `meister node ls` said `READY Unprivileged` for
# ever — which is not "no fabric volumes here" but "place NOTHING on this
# node", not even a guest with a plain filesystem volume. It is what blocked
# L12.
#
# Both directions, because the default matters as much as the switch: an
# agent node that says nothing still carries both sections.
{ nixpkgs, lib, pkgs, system, self }:

let
  agentToml = extra: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        nixpkgs.overlays = [ self.overlays.default ];
        networking.hostName = "probe";
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.managed
      {
        meisterstack.roles = [ "agent" ];
        meisterstack.managed.enable = true;
        meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
      }
      extra
    ];
  }).config.environment.etc."meisterstack/agent.toml".source;

  withFabric = agentToml { };
  withoutFabric = agentToml { meisterstack.agent.nvmeTcp.enable = false; };
in
pkgs.runCommand "no-fabric-no-claim" { } ''
  if ! grep -q '^\[volume.nvmeof\]' ${withFabric}; then
    echo "an agent node no longer registers the NVMe-oF attacher by default"
    exit 1
  fi
  if grep -q 'volume.nvmeof' ${withoutFabric}; then
    echo "-> nvmeTcp.enable = false and the node still claims the fabric:"
    grep -n 'volume' ${withoutFabric}
    echo "   the scheduler reads that claim, the attacher cannot honour it,"
    echo "   and the node stays Unprivileged for everything."
    exit 1
  fi
  # And what it still has: a node without a fabric is an ordinary node.
  grep -q '^\[paths\]' ${withoutFabric} || { echo "the config lost more than the fabric"; exit 1; }
  echo "a node that says nvmeTcp.enable = false registers no nvmeof backend"
  touch $out
''
