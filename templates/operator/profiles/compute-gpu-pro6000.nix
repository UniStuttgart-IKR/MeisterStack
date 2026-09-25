# SPDX-License-Identifier: MIT
# NVIDIA host profile: IOMMU/VFIO settings plus an optional Leandro backend.
# Hardware availability and working GPU execution require separate host validation.
{ lib
  # The GPU stack, as flake.nix hands it over: the whole flake, or `null`.
, leandro ? null
, system ? "x86_64-linux"
}:
{ ... }:
let
  # NVRM configuration requires both the vhost backend and the profile utility.
  gpu = lib.optionalAttrs (leandro != null) {
    device.nvrm = {
      binary = "${leandro.packages.${system}.vhost-user-nvrm}/bin/vhost-user-nvrm";
      vgpuprofile = "${leandro.packages.${system}.leandro}/bin/vgpuprofile";
    };
  };
in
{
  # Enable VFIO and Intel IOMMU settings. Adjust kernel parameters for the host CPU.
  boot.kernelModules = [ "vfio-pci" ];
  boot.kernelParams = [ "intel_iommu=on" "iommu=pt" ];

  # Select PCI devices in the host module; record declared hardware in the inventory.

  # Without Leandro, no NVRM backend is configured.
  meisterstack.agent.settings = gpu;

  # Explain the missing optional backend during evaluation.
  warnings = lib.optional (leandro == null) (
    "profiles/compute-gpu-pro6000.nix configures the IOMMU and vfio-pci, and no NVIDIA "
    + "backend: the `leandro` input is not declared in flake.nix. Uncomment it there, or "
    + "this fleet's GPU hosts carry cards that nothing hands to a guest."
  );
}
