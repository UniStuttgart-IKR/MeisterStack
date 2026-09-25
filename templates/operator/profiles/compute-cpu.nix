# SPDX-License-Identifier: MIT
# CPU profile without external GPU inputs.
{ config, lib, pkgs, ... }:
{
  # Disable unused routing and NVMe/TCP services for this profile.
  meisterstack.agent.frr.enable = lib.mkDefault false;
  meisterstack.agent.nvmeTcp.enable = lib.mkDefault false;
}
