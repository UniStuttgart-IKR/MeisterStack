# SPDX-License-Identifier: MIT
# A host that collects its own logs and metrics.
#
# The collector's own configuration is not TOML and is written by the BOOT
# renderer today, which a managed host does not have — so
# `meisterstack.observability.enable` is off on a managed host and turning it
# on here would give you a unit whose config file nobody writes. The honest
# road for now is an EXTERNAL observability service, declared in the
# inventory as `[[service]] kind = "observability"`, which meister-deploy
# observes and never configures.
#
# This file exists so that the profile name in fleet.toml resolves, and it
# says what it does not do.
{ config, lib, pkgs, ... }:
{
  warnings = [
    "profiles/observability-local.nix cannot configure a collector yet: the "
    + "alloy configuration is written by the boot renderer, which a managed "
    + "host has none of. Declare an external observability service in "
    + "fleet.toml instead."
  ];
}
