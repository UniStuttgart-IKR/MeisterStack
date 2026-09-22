# SPDX-License-Identifier: MIT
# The profiles of this fleet. A host gets the ones its inventory entry names.
{ lib }:
{
  base = import ./profiles/base.nix;
  controller = import ./profiles/controller.nix;
  compute-cpu = import ./profiles/compute-cpu.nix;
  compute-gpu-pro6000 = import ./profiles/compute-gpu-pro6000.nix;
  observability-local = import ./profiles/observability-local.nix;
}
