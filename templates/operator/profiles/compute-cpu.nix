# SPDX-License-Identifier: MIT
# A workload carrier with no GPU: the case that has to build without any
# extra input at all.
{ config, lib, pkgs, ... }:
{
  # The routing daemon and the NVMe-over-fabrics module follow the agent role
  # by default. A carrier that neither routes nor attaches remote volumes
  # says so here and carries neither.
  meisterstack.agent.frr.enable = lib.mkDefault false;
  meisterstack.agent.nvmeTcp.enable = lib.mkDefault false;
}
