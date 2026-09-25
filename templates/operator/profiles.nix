# SPDX-License-Identifier: MIT
# Map inventory profile names to host modules.
# Only the GPU profile consumes the optional Leandro input.
{ lib, leandro ? null }:
{
  base = import ./profiles/base.nix;
  controller = import ./profiles/controller.nix;
  compute-cpu = import ./profiles/compute-cpu.nix;
  compute-gpu-pro6000 = import ./profiles/compute-gpu-pro6000.nix { inherit lib leandro; };
  observability-local = import ./profiles/observability-local.nix;
  single-node = import ./profiles/single-node.nix;
}
