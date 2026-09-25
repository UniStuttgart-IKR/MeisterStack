# SPDX-License-Identifier: MIT
# Standalone agent and local CLI; no controller role or connection.
# Add authorized local users to operators and combine with a hardware profile.
{ ... }:
{
  meisterstack.singleNode.enable = true;
  meisterstack.singleNode.operators = [ ];
  # A single node has no fabric to join: no routing daemon, no NVMe-oF.
  meisterstack.agent.frr.enable = false;
  meisterstack.agent.nvmeTcp.enable = false;
}
