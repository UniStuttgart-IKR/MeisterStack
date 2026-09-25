# SPDX-License-Identifier: MIT
# The profiles of this fleet. A host gets the ones its inventory entry names.
#
# `leandro` is the GPU stack and is `null` unless flake.nix declares that
# input. Only the GPU profile looks at it, and it configures no card when it
# is not there — which is what lets a CPU-only fleet build without anybody's
# home directory.
{ lib, leandro ? null }:
{
  base = import ./profiles/base.nix;
  controller = import ./profiles/controller.nix;
  compute-cpu = import ./profiles/compute-cpu.nix;
  compute-gpu-pro6000 = import ./profiles/compute-gpu-pro6000.nix { inherit lib leandro; };
  observability-local = import ./profiles/observability-local.nix;
  single-node = import ./profiles/single-node.nix;
}
