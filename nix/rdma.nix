# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Install RDMA diagnostic and benchmark tools on enabled agents. Inventory
# enables them for declared RDMA NICs. No daemon is started; operators can
# replace the package list with a compatible vendor toolchain.
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

        It is what a fleet's RDMA verification suite drives, over ssh, one
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
