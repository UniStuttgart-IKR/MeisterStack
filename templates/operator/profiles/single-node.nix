# SPDX-License-Identifier: MIT
# One machine, the agent and the CLI, and nobody above it.
#
# The profile of a host that is its own fleet: a workstation or a lab box
# that makes guests the way the fleet does — the same VMM, the same spec,
# the same device drivers — without a cloud, a cluster or a scheduler. The
# inventory entry of such a host names the role `agent` and nothing else,
# no group and no `controller_group`; nix/single-node.nix refuses anything
# else and says why.
#
# Combine it with a carrier profile for the hardware — `compute-gpu-pro6000`
# for the card, or nothing for a CPU box — and put the people who may drive
# the node into `operators`: that is a membership in the `meister` group,
# which owns the agent's socket. Root needs no entry.
{ ... }:
{
  meisterstack.singleNode.enable = true;
  meisterstack.singleNode.operators = [ ];
  # A single node has no fabric to join: no routing daemon, no NVMe-oF.
  meisterstack.agent.frr.enable = false;
  meisterstack.agent.nvmeTcp.enable = false;
}
