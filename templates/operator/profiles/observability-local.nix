# SPDX-License-Identifier: MIT
# Placeholder profile: it does not configure a local collector.
# Use an external observability service until a managed collector config is supplied.
{ config, lib, pkgs, ... }:
{
  warnings = [
    "profiles/observability-local.nix cannot configure a collector yet: the "
    + "alloy configuration is written by the boot renderer, which a managed "
    + "host has none of. Declare an external observability service in "
    + "fleet.toml instead."
  ];
}
