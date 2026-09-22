# SPDX-License-Identifier: MIT
# A workload carrier with an NVIDIA RTX PRO 6000 in it.
#
# This profile needs the `leandro` input (the GPU stack: vhost-user-nvrm and
# the vgpu profile tool) — it is commented out in flake.nix, and so is the
# line that uses it here. A CPU-only fleet has to build without either, which
# is scenario L01: nothing in this repository may need somebody's home
# directory.
#
# What this profile does NOT do is claim the card works. `meister-deploy
# verify --suite gpu` is what says that, on the machine, with a deterministic
# computation whose result is checked — and `capabilities = ["vfio"]` in the
# inventory is what makes that suite required rather than `not_applicable`.
{ config, lib, pkgs, ... }:
{
  # The devices the agent hands to guests, and the driver behind them. Fill
  # in the PCI addresses from `lspci -nn` of the machine in question; the
  # inventory's `hardware.gpus` is where they are declared for the fleet.
  #
  # boot.kernelModules = [ "vfio-pci" ];
  # boot.kernelParams = [ "intel_iommu=on" "iommu=pt" ];
  #
  # The vhost-user backend for NVIDIA's resource manager, out of the leandro
  # input rather than out of a build somebody did by hand:
  #
  # meisterstack.agent.settings.device.nvrm.binary =
  #   "${inputs.leandro.packages.x86_64-linux.vhost-user-nvrm}/bin/vhost-user-nvrm";

  # Until the two blocks above are filled in, this profile is a name and
  # nothing else. It is here so that a GPU host has somewhere to put its
  # hardware, not so that it looks configured.
  warnings = [
    "profiles/compute-gpu-pro6000.nix is a stub: it configures no card yet."
  ];
}
