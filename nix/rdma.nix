# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The fabric tools a host with an RDMA card needs, and nothing else.
#
# `meister-deploy verify --suite rdma` runs three measurements between two
# hosts that DECLARE an RDMA nic on the same storage network: a round trip
# (`rping`), a latency (`ib_send_lat`) and a bandwidth (`ib_write_bw`). All
# three are server-on-A, client-on-B, and all three need the binary to be
# there — so the closure of a host with such a card carries them, and a host
# without one carries nothing new at all.
#
# Three things worth reading before changing this:
#
# * **It is role- and hardware-gated, twice.** The option defaults to `false`,
#   and `nix/lib/inventory.nix` turns it on for a host whose
#   `hardware.nics[].rdma` is true AND which has the agent role. A service
#   module that put fabric tools on every machine would be a service module
#   deciding something about the machine, which is exactly what
#   `checks.services-are-pure` exists to refuse.
# * **`environment.systemPackages` and not a unit.** Nothing here runs on its
#   own. The suite reaches the binaries over ssh, as a person would, and a
#   daemon that existed only to be measured would be a daemon to keep alive.
# * **`perftest` is built by this repository** (nix/packages/perftest.nix):
#   the pinned nixpkgs has `rdma-core` and no `perftest`, measured. The
#   package option below is the way out for an operator who has their
#   vendor's build — Mellanox ships one — without patching this file.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
  rdma = cfg.agent.rdma;
in
{
  options.meisterstack.agent.rdma = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      defaultText = lib.literalExpression ''false, and the inventory turns it on for a host whose hardware.nics declares rdma'';
      description = ''
        Whether this machine carries the user-space tools of an RDMA fabric:
        `rping` and `ibv_devinfo` out of rdma-core, `ib_send_lat` and
        `ib_write_bw` out of perftest.

        It is what `meister-deploy verify --suite rdma` drives, over ssh, one
        end of a declared pair at a time. Without it that suite finds no
        binary on the host and says `skipped` with the sentence — never
        `pass`, because a fabric nobody could measure is not a fabric that
        works.

        Off by default and turned on by the inventory for a host whose
        `hardware.nics[].rdma` is true: a card is a fact about a machine, and
        the inventory is where the facts about machines are written down.
      '';
    };

    packages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ pkgs.rdma-core (pkgs.callPackage ./packages/perftest.nix { }) ];
      defaultText = lib.literalExpression ''[ pkgs.rdma-core (pkgs.callPackage ./packages/perftest.nix { }) ]'';
      description = ''
        The packages `rdma.enable` puts on the machine.

        An option rather than a constant because the two builds are not
        equivalent everywhere: a Mellanox estate has MLNX_OFED, whose
        `ib_write_bw` is the one its support contract talks about, and an
        operator who replaces this list gets their own without a fork. The
        suite names the binaries and not the packages, so anything that
        provides `rping`, `ibv_devinfo`, `ib_send_lat` and `ib_write_bw` on
        `PATH` does.
      '';
    };
  };

  config = lib.mkIf (rdma.enable && builtins.elem "agent" cfg.unitsFor) {
    environment.systemPackages = rdma.packages;
  };
}
