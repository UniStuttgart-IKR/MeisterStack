# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A managed host's units name the STORE.
#
# The switch is one option — `meisterstack.binDir`, which nix/managed.nix
# derives from `meisterstack.runtime` — and this check is what holds it: every
# ExecStart of this stack, the hypervisor path in the agent's config and the
# conditions that used to wait for a push have to come out of the package. A
# single /opt/meisterstack/bin left in a unit file would be a host waiting
# forever for an rsync that is never coming.
{ nixpkgs, lib, pkgs, system, self }:

  let
    probe = (nixpkgs.lib.nixosSystem {
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
          meisterstack.roles = [ "cloud" "cluster" "agent" ];
          meisterstack.managed.enable = true;
          meisterstack.managed.trustedPublicKeys = [ "probe:not-a-real-key" ];
        }
      ];
    }).config;
    top = probe.system.build.toplevel;
    runtime = probe.meisterstack.binDir;
  in
  pkgs.runCommand "managed-uses-the-package" { } ''
    units=${top}/etc/systemd/system
    if grep -rl '/opt/meisterstack/bin' $units; then
      echo "-> a managed host still takes a binary from a push directory"
      exit 1
    fi
    for u in meister-cloud-controller meister-cluster-controller meister-agent; do
      grep -q "ExecStart=${runtime}/$u " $units/$u.service                 || { echo "$u.service does not start ${runtime}/$u"; exit 1; }
      test -x ${runtime}/$u || { echo "${runtime}/$u is not there"; exit 1; }
    done
    # The agent starts guests with the hypervisor out of the SAME
    # directory, because `binDir` is a directory and its config names
    # the binary in it.
    test -x ${runtime}/cloud-hypervisor               || { echo "the hypervisor is not in ${runtime}"; exit 1; }
    grep -q '${runtime}/cloud-hypervisor'               ${probe.environment.etc."meisterstack/agent.toml".source}               || { echo "agent.toml does not name the hypervisor in binDir"; exit 1; }
    # And what the conditions say now: the keys, which are pushed on
    # both roads, and never a binary, which on this road cannot be
    # missing.
    if grep -h ConditionPathExists $units/meister-*.service | grep -q '/bin/'; then
      echo "-> a unit still waits for a binary that is part of its own system"
      grep -h ConditionPathExists $units/meister-*.service
      exit 1
    fi
    grep -q 'ConditionPathExists=.*/pki/ca.crt' $units/meister-agent.service               || { echo "the agent no longer waits for its CA"; exit 1; }
    echo "the units of a managed host name ${runtime} and nothing under /opt"
    touch $out
  ''
